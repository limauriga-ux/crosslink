package gui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/daemonipc"
	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"
	"github.com/limauriga-ux/crosslink/internal/profile"
)

type Service struct {
	// daemonSourcePath is the checksum-pinned staging copy extracted by the
	// unprivileged GUI. daemonPath is the executable a privileged service uses.
	daemonSourcePath string
	daemonPath       string
	daemonSHA256     string
	daemonReplaced   bool
	configPath       string
	logPath          string
	pidPath          string
	workDir          string
	appVersion       string
	runner           Runner
	runtimePaths     config.DaemonRuntimePaths
	runtimePathErr   error
	authorizedUID    int
	authorizedGID    int
}

// privilegedRunTimeout bounds osascript invocations that pop the admin
// password dialog. The runner's default 15s ceiling killed the dialog before
// new users finished typing their password — leaving them with no daemon, no
// logs and no rules. Five minutes is generous; the kernel reaps the process
// the moment the user accepts or cancels.
const privilegedRunTimeout = 5 * time.Minute

func NewService(opts Options) *Service {
	if opts.ConfigPath == "" {
		opts.ConfigPath = filepath.Join(defaultCrosslinkDir(), "config.json")
	}
	opts.ConfigPath = expandHome(opts.ConfigPath)
	if absolute, err := filepath.Abs(opts.ConfigPath); err == nil {
		opts.ConfigPath = absolute
	}
	runtimePaths, runtimePathErr := config.ResolveDaemonRuntimePaths(opts.ConfigPath, "")
	if runtimePathErr != nil {
		// Keep the service constructible for diagnostics. Every privileged
		// operation checks runtimePathErr before executing a helper.
		dataDir := filepath.Dir(opts.ConfigPath)
		runtimePaths = config.DaemonRuntimePaths{
			ConfigPath: opts.ConfigPath,
			DataDir:    dataDir,
			PIDFile:    filepath.Join(dataDir, "crosslink.pid"),
			Socket:     filepath.Join(dataDir, "daemon.sock"),
		}
	}
	if opts.DaemonPath == "" {
		opts.DaemonPath = filepath.Join(runtimePaths.DataDir, "bin", executableName("crosslink-daemon"))
	}
	if opts.PrivilegedDaemonPath == "" {
		opts.PrivilegedDaemonPath = defaultPrivilegedDaemonPath(runtime.GOOS, opts.DaemonPath)
	}
	if opts.LogPath == "" {
		opts.LogPath = defaultServiceLogPath(runtime.GOOS, filepath.Join(runtimePaths.DataDir, "crosslink.log"))
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{Timeout: 15 * time.Second}
	}
	uid, gid := currentAuthorizedIDs()
	if opts.AuthorizedIdentitySet {
		uid = opts.AuthorizedUID
		gid = opts.AuthorizedGID
	}
	workDir := runtimePaths.DataDir
	if candidate := strings.TrimSpace(opts.WorkDir); candidate != "" {
		if absolute, absErr := filepath.Abs(expandHome(candidate)); absErr == nil && filepath.Clean(absolute) == runtimePaths.DataDir {
			workDir = absolute
		}
	}
	return &Service{
		daemonSourcePath: opts.DaemonPath,
		daemonPath:       opts.PrivilegedDaemonPath,
		daemonSHA256:     strings.ToLower(strings.TrimSpace(opts.DaemonSHA256)),
		daemonReplaced:   opts.DaemonReplaced,
		configPath:       runtimePaths.ConfigPath,
		logPath:          opts.LogPath,
		pidPath:          runtimePaths.PIDFile,
		workDir:          workDir,
		appVersion:       opts.AppVersion,
		runner:           opts.Runner,
		runtimePaths:     runtimePaths,
		runtimePathErr:   runtimePathErr,
		authorizedUID:    uid,
		authorizedGID:    gid,
	}
}

// GetVersion returns the application version injected at build time.
// The actual value is set via the AppVersion field on Options.
func (s *Service) GetVersion() string {
	return s.appVersion
}

// GetAppState returns current binary/config/log paths and daemon status.
func (s *Service) GetAppState() AppState {
	status := s.GetDaemonStatus()
	return AppState{
		DaemonPath: s.daemonPath,
		ConfigPath: s.configPath,
		LogPath:    s.logPath,
		PidPath:    s.pidPath,
		Status:     status,
	}
}

func (s *Service) LoadConfig(path string) ConfigDocument {
	path = s.configPathOr(path)
	cfg, err := config.LoadConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.DefaultConfig()
			if res := s.SaveConfig(path, cfg); !res.OK {
				return ConfigDocument{OK: false, Path: path, Error: strings.Join(res.Errors, "\n")}
			}
			return ConfigDocument{OK: true, Path: path, Config: cfg}
		}
		return ConfigDocument{OK: false, Path: path, Error: err.Error()}
	}
	return ConfigDocument{OK: true, Path: path, Config: cfg}
}

func (s *Service) EnsureUserConfig(path string) CommandResult {
	path = s.configPathOr(path)
	cfg, err := config.LoadConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg = config.DefaultConfig()
		} else {
			return CommandResult{OK: false, Summary: "加载配置失败: " + err.Error()}
		}
	}
	res := s.SaveConfig(path, cfg)
	if !res.OK {
		return CommandResult{OK: false, Summary: "配置不可写: " + strings.Join(res.Errors, "; ")}
	}
	return CommandResult{OK: true}
}

func (s *Service) SaveConfig(path string, cfg *config.Config) ValidationResult {
	if cfg == nil {
		return ValidationResult{OK: false, Errors: []string{"config is nil"}}
	}
	path = s.configPathOr(path)
	if err := cfg.BindConfigPath(expandHome(path)); err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	if res := s.ValidateConfig(cfg); !res.OK {
		return res
	}
	if err := cfg.EnsureDataDir(); err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	previous, previousErr := os.ReadFile(expandHome(path))
	previousExists := previousErr == nil
	if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
		return ValidationResult{OK: false, Errors: []string{previousErr.Error()}}
	}
	if err := profile.SaveAtomic(path, append(data, '\n')); err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	if status := s.GetDaemonStatus(); status.State == "running" {
		if reload := s.ReloadConfig(); !reload.OK {
			rollbackErr := rollbackManagedFile(path, previous, previousExists)
			recovery := s.ReloadConfig()
			detail := reload.Summary
			if detail == "" {
				detail = reload.Details
			}
			if rollbackErr != nil {
				detail += "; rollback failed: " + rollbackErr.Error()
			} else if !recovery.OK {
				detail += "; previous core recovery failed: " + recovery.Summary
			}
			return ValidationResult{OK: false, Errors: []string{detail}}
		}
	}
	return ValidationResult{OK: true}
}

func (s *Service) ValidateConfig(cfg *config.Config) ValidationResult {
	if cfg == nil {
		return ValidationResult{OK: false, Errors: []string{"config is nil"}}
	}
	if err := cfg.BindConfigPath(expandHome(s.configPath)); err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	if err := cfg.Validate(); err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	if err := cfg.ValidateDaemonPaths(); err != nil {
		return ValidationResult{OK: false, Errors: []string{err.Error()}}
	}
	return ValidationResult{OK: true}
}

func (s *Service) GetProxyProfile() ProxyProfileResult {
	path, err := s.proxyProfilePath()
	if err != nil {
		return ProxyProfileResult{OK: false, Error: err.Error()}
	}
	content, err := profile.Read(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ProxyProfileResult{OK: true, Path: path, Exists: false}
		}
		return ProxyProfileResult{OK: false, Path: path, Error: err.Error()}
	}
	_, report, err := profile.Normalize(content)
	if err != nil {
		return ProxyProfileResult{OK: false, Path: path, Exists: true, Content: string(content), Error: err.Error()}
	}
	return proxyProfileResult(path, string(content), report)
}

func (s *Service) SaveProxyProfile(content string) ProxyProfileResult {
	path, err := s.proxyProfilePath()
	if err != nil {
		return ProxyProfileResult{OK: false, Error: err.Error()}
	}
	normalized, report, err := profile.Normalize([]byte(content))
	if err != nil {
		return ProxyProfileResult{OK: false, Path: path, Error: err.Error()}
	}
	previous, previousErr := os.ReadFile(expandHome(path))
	previousExists := previousErr == nil
	if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
		return ProxyProfileResult{OK: false, Path: path, Error: previousErr.Error()}
	}
	if err := profile.SaveAtomic(path, append(normalized, '\n')); err != nil {
		return ProxyProfileResult{OK: false, Path: path, Error: err.Error()}
	}
	if status := s.GetDaemonStatus(); status.State == "running" {
		if reload := s.ReloadConfig(); !reload.OK {
			rollbackErr := rollbackManagedFile(path, previous, previousExists)
			recovery := s.ReloadConfig()
			detail := reload.Summary
			if rollbackErr != nil {
				detail += "; rollback failed: " + rollbackErr.Error()
			} else if !recovery.OK {
				detail += "; previous core recovery failed: " + recovery.Summary
			}
			return ProxyProfileResult{OK: false, Path: path, Exists: previousExists, Content: string(previous), Error: detail}
		}
	}
	return proxyProfileResult(path, string(normalized), report)
}

func rollbackManagedFile(path string, previous []byte, existed bool) error {
	if existed {
		return profile.SaveAtomic(path, previous)
	}
	err := os.Remove(expandHome(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Service) GetRulePlan() RulePlanResult {
	path, err := s.rulePlanPath()
	if err != nil {
		return RulePlanResult{OK: false, Error: err.Error()}
	}
	plan, err := profile.LoadRulePlan(path)
	if err != nil {
		return RulePlanResult{OK: false, Path: path, Error: err.Error()}
	}
	context, err := s.ruleContext()
	if err != nil {
		return RulePlanResult{OK: false, Path: path, Prepend: plan.Prepend, Append: plan.Append, Error: err.Error()}
	}
	return rulePlanResult(path, plan, context)
}

func (s *Service) SaveRulePlan(prepend, appendRules []string) RulePlanResult {
	path, err := s.rulePlanPath()
	if err != nil {
		return RulePlanResult{OK: false, Error: err.Error()}
	}
	plan, err := profile.NormalizeRulePlan(profile.RulePlan{
		Version: profile.RulePlanVersion,
		Prepend: prepend,
		Append:  appendRules,
	})
	if err != nil {
		return RulePlanResult{OK: false, Path: path, Prepend: prepend, Append: appendRules, Error: err.Error()}
	}
	context, err := s.ruleContext()
	if err != nil {
		return RulePlanResult{OK: false, Path: path, Prepend: plan.Prepend, Append: plan.Append, Error: err.Error()}
	}
	if _, _, err := profile.CompileRulePlan(plan, context.Targets); err != nil {
		result := rulePlanResult(path, plan, context)
		result.OK = false
		result.Error = err.Error()
		return result
	}

	previous, previousErr := os.ReadFile(expandHome(path))
	previousExists := previousErr == nil
	if previousErr != nil && !errors.Is(previousErr, os.ErrNotExist) {
		return RulePlanResult{OK: false, Path: path, Error: previousErr.Error()}
	}
	if err := profile.SaveRulePlanAtomic(path, plan); err != nil {
		return RulePlanResult{OK: false, Path: path, Error: err.Error()}
	}
	if status := s.GetDaemonStatus(); status.State == "running" {
		if reload := s.ReloadConfig(); !reload.OK {
			rollbackErr := rollbackManagedFile(path, previous, previousExists)
			recovery := s.ReloadConfig()
			detail := reload.Summary
			if rollbackErr != nil {
				detail += "; rollback failed: " + rollbackErr.Error()
			} else if !recovery.OK {
				detail += "; previous core recovery failed: " + recovery.Summary
			}
			result := s.GetRulePlan()
			result.OK = false
			result.Error = detail
			return result
		}
	}
	return rulePlanResult(path, plan, context)
}

func rulePlanResult(path string, plan profile.RulePlan, context profile.RuleContext) RulePlanResult {
	targets := append([]string{}, context.Targets...)
	targets = append(targets, "DIRECT", "REJECT", "CORP", "OPENVPN")
	result := RulePlanResult{
		OK:               true,
		Path:             path,
		Prepend:          append([]string{}, plan.Prepend...),
		Append:           append([]string{}, plan.Append...),
		Targets:          targets,
		ProfileRuleCount: context.ProfileRuleCount,
		Final:            context.Final,
	}

	if _, _, err := profile.CompileRulePlan(plan, context.Targets); err != nil {
		result.OK = false
		result.Error = err.Error()
	}
	return result
}

func (s *Service) ImportProxyProfileURL(rawURL string) ProxyProfileResult {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" || parsed.Scheme != "https" {
		return ProxyProfileResult{OK: false, Error: "订阅地址必须是有效的 HTTPS URL"}
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many subscription redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("subscription redirect downgraded from HTTPS")
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, parsed.String(), nil)
	if err != nil {
		return ProxyProfileResult{OK: false, Error: err.Error()}
	}
	request.Header.Set("User-Agent", "CrossLink/1")
	response, err := client.Do(request)
	if err != nil {
		return ProxyProfileResult{OK: false, Error: "下载订阅失败: " + err.Error()}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ProxyProfileResult{OK: false, Error: fmt.Sprintf("下载订阅失败: HTTP %d", response.StatusCode)}
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, profile.MaxBytes+1))
	if err != nil {
		return ProxyProfileResult{OK: false, Error: "读取订阅失败: " + err.Error()}
	}
	if len(content) > profile.MaxBytes {
		return ProxyProfileResult{OK: false, Error: fmt.Sprintf("订阅超过 %d 字节", profile.MaxBytes)}
	}
	return s.SaveProxyProfile(string(content))
}

func (s *Service) proxyProfilePath() (string, error) {
	cfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return "", err
	}
	return cfg.ProxyProfilePath()
}

func (s *Service) rulePlanPath() (string, error) {
	cfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return "", err
	}
	return cfg.RulePlanPath()
}

func (s *Service) ruleContext() (profile.RuleContext, error) {
	context := profile.RuleContext{Final: "direct"}
	path, err := s.proxyProfilePath()
	if err != nil {
		if strings.Contains(err.Error(), "core.profile is empty") {
			return context, nil
		}
		return profile.RuleContext{}, err
	}
	content, err := profile.Read(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return context, nil
		}
		return profile.RuleContext{}, err
	}
	return profile.InspectRuleContext(content)
}

func proxyProfileResult(path, content string, report profile.Report) ProxyProfileResult {
	return ProxyProfileResult{
		OK:        true,
		Path:      path,
		Exists:    true,
		Content:   content,
		Format:    report.Format,
		Nodes:     report.Nodes,
		Endpoints: report.Endpoints,
		Warnings:  report.Warnings,
	}
}

func (s *Service) GetOpenVPNProfile() OpenVPNProfileResult {
	cfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return OpenVPNProfileResult{OK: false, Error: err.Error(), Warnings: []string{}}
	}
	dataDir, path, err := cfg.OpenVPNProfilePath()
	if err != nil {
		return OpenVPNProfileResult{OK: false, Error: err.Error(), Warnings: []string{}}
	}
	managed, err := openvpnprofile.LoadManaged(dataDir, path)
	if errors.Is(err, os.ErrNotExist) {
		return OpenVPNProfileResult{OK: true, Exists: false, Path: path, Warnings: []string{}}
	}
	if err != nil {
		return OpenVPNProfileResult{OK: false, Path: path, Error: err.Error(), Warnings: []string{}}
	}
	return openVPNProfileResult(path, managed.Report())
}

func (s *Service) ImportOpenVPNProfile(request OpenVPNImportRequest) OpenVPNProfileResult {
	cfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return OpenVPNProfileResult{OK: false, Error: err.Error(), Warnings: []string{}}
	}
	dataDir, path, err := cfg.OpenVPNProfilePath()
	if err != nil {
		return OpenVPNProfileResult{OK: false, Error: err.Error(), Warnings: []string{}}
	}
	managed, report, err := openvpnprofile.Import(openvpnprofile.ImportOptions{
		OVPNPath:       request.OVPNPath,
		CAPath:         request.CAPath,
		PKCS12Path:     request.PKCS12Path,
		PKCS12Password: request.PKCS12Password,
		LegacyBFCompat: request.LegacyBFCompat,
	})
	request.PKCS12Password = ""
	if err != nil {
		return OpenVPNProfileResult{OK: false, Path: path, Error: err.Error(), Warnings: []string{}}
	}
	if err := openvpnprofile.SaveManaged(dataDir, path, managed); err != nil {
		return OpenVPNProfileResult{OK: false, Path: path, Error: err.Error(), Warnings: []string{}}
	}
	return openVPNProfileResult(path, report)
}

func (s *Service) RemoveOpenVPNProfile() OpenVPNProfileResult {
	cfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return OpenVPNProfileResult{OK: false, Error: err.Error(), Warnings: []string{}}
	}
	dataDir, path, err := cfg.OpenVPNProfilePath()
	if err != nil {
		return OpenVPNProfileResult{OK: false, Error: err.Error(), Warnings: []string{}}
	}
	// A live daemon owns OpenVPN state. Let it serialize the active-state
	// check and file removal against connect/disconnect actions; a local
	// status check followed by os.Remove would have a TOCTOU race.
	if status := s.GetDaemonStatus(); status.State == "running" {
		response, sendErr := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionOpenVPNRemoveProfile})
		if sendErr != nil {
			return OpenVPNProfileResult{OK: false, Path: path, Error: "daemon unreachable: " + sendErr.Error(), Warnings: []string{}}
		}
		if !response.OK {
			return OpenVPNProfileResult{OK: false, Path: path, Error: response.Error, Warnings: []string{}}
		}
		return OpenVPNProfileResult{OK: true, Exists: false, Path: path, Warnings: []string{}}
	}
	if err := openvpnprofile.RemoveManaged(dataDir, path); err != nil {
		return OpenVPNProfileResult{OK: false, Path: path, Error: err.Error(), Warnings: []string{}}
	}
	return OpenVPNProfileResult{OK: true, Exists: false, Path: path, Warnings: []string{}}
}

func openVPNProfileResult(path string, report openvpnprofile.ImportReport) OpenVPNProfileResult {
	return OpenVPNProfileResult{
		OK:                   true,
		Exists:               true,
		Path:                 path,
		Name:                 report.Name,
		Server:               report.Server,
		Network:              report.Network,
		Routes:               report.Routes,
		Domains:              report.Domains,
		DNSServers:           report.DNSServers,
		RequiresCredentials:  report.RequiresCredentials,
		LegacyCipherFallback: report.LegacyCipherFallback,
		CertificateExpiresAt: report.CertificateExpiresAt,
		Warnings:             append([]string{}, report.Warnings...),
	}
}

func (s *Service) StartDaemon(path string) CommandResult {
	path = s.configPathOr(path)
	if s.runtimePathErr != nil {
		return CommandResult{OK: false, Summary: s.runtimePathErr.Error()}
	}
	if status := s.GetDaemonStatus(); status.State == "running" {
		return CommandResult{OK: true, Summary: status.Summary}
	}
	if res := s.EnsureUserConfig(path); !res.OK {
		return res
	}
	res := s.privilegedCommand(s.daemonRunArgs(false)...)
	res = normalizeDaemonCommandResult(res)
	if !res.OK {
		return res
	}
	if status := s.waitForDaemonRunning(5 * time.Second); status.State == "running" {
		return CommandResult{OK: true, Summary: status.Summary, Details: res.Details}
	}
	res.OK = false
	res.Summary = "daemon did not become running"
	res.Details = strings.TrimSpace(res.Details + "\n\n" + s.GetDaemonStatus().Summary)
	return res
}

func (s *Service) StopDaemon() CommandResult {
	if s.runtimePathErr != nil {
		return CommandResult{OK: false, Summary: s.runtimePathErr.Error()}
	}
	args := append([]string{"stop"}, s.daemonRunArgs(false)...)
	return s.privilegedCommand(args...)
}

func (s *Service) RestartDaemon(path string) CommandResult {
	stop := s.StopDaemon()
	if !stop.OK && !strings.Contains(strings.ToLower(stop.Summary+stop.Details), "daemon not running") {
		return stop
	}
	return s.StartDaemon(path)
}

func (s *Service) GetDaemonStatus() DaemonStatus {
	if pid, err := readPidFile(s.pidPath); err == nil {
		if isProcessRunning(pid) {
			return DaemonStatus{
				State:   "running",
				PID:     pid,
				Summary: fmt.Sprintf("daemon running (pid %d)", pid),
			}
		}
		return DaemonStatus{State: "stopped", Summary: fmt.Sprintf("stale pid file: process %d is not running", pid)}
	}

	return DaemonStatus{State: "stopped", Summary: "daemon not running"}
}

func (s *Service) command(args ...string) CommandResult {
	return s.commandPath(s.daemonPath, args...)
}

func (s *Service) sourceCommand(args ...string) CommandResult {
	return s.commandPath(s.daemonSourcePath, args...)
}

func (s *Service) privilegedCommand(args ...string) CommandResult {
	if runtime.GOOS != "darwin" {
		return s.command(args...)
	}
	command := shellQuote(s.daemonPath)
	for _, arg := range args {
		command += " " + shellQuote(arg)
	}
	if s.workDir != "" {
		command = "cd " + shellQuote(s.workDir) + " && " + command
	}
	osa := fmt.Sprintf("do shell script %s with administrator privileges", appleScriptQuote(command))
	res := s.runner.Run(nilContext(), RunRequest{
		Path:    "osascript",
		Args:    []string{"-e", osa},
		Dir:     s.workDir,
		Timeout: privilegedRunTimeout,
	})
	return commandResult(res)
}

func (s *Service) commandPath(path string, args ...string) CommandResult {
	res := s.runner.Run(context.Background(), RunRequest{
		Path: path,
		Args: args,
		Dir:  s.workDir,
	})
	return commandResult(res)
}

func commandResult(res RunResult) CommandResult {
	output := strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
	details := commandDetails(res)
	if res.OK {
		return CommandResult{OK: true, Summary: output, Details: details}
	}
	summary := firstOutputLine(res.Stderr)
	if summary == "" {
		summary = firstOutputLine(res.Stdout)
	}
	if res.TimedOut {
		summary = "command timed out"
	}
	if summary == "" {
		summary = res.Error
	}
	if summary == "" && res.ExitCode != 0 {
		summary = fmt.Sprintf("command failed with exit code %d", res.ExitCode)
	}
	return CommandResult{OK: false, Summary: summary, Details: details, ExitCode: res.ExitCode}
}

func commandDetails(res RunResult) string {
	var parts []string
	if stdout := strings.TrimSpace(res.Stdout); stdout != "" {
		parts = append(parts, "stdout:\n"+stdout)
	}
	if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
		parts = append(parts, "stderr:\n"+stderr)
	}
	if res.ExitCode != 0 {
		parts = append(parts, fmt.Sprintf("exit code: %d", res.ExitCode))
	}
	if res.TimedOut {
		parts = append(parts, "timeout: true")
	}
	if errText := strings.TrimSpace(res.Error); errText != "" {
		parts = append(parts, "error: "+errText)
	}
	return strings.Join(parts, "\n\n")
}

func firstOutputLine(text string) string {
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func normalizeDaemonCommandResult(res CommandResult) CommandResult {
	if res.OK {
		return res
	}
	text := strings.ToLower(res.Summary + "\n" + res.Details)
	if strings.Contains(text, "daemon already running") {
		res.OK = true
		res.ExitCode = 0
	}
	return res
}

func (s *Service) waitForDaemonRunning(timeout time.Duration) DaemonStatus {
	deadline := time.Now().Add(timeout)
	for {
		status := s.GetDaemonStatus()
		if status.State == "running" {
			return status
		}
		if time.Now().After(deadline) {
			return status
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (s *Service) configPathOr(_ string) string {
	// The daemon is a single-user managed service. Never let a caller select a
	// second config root after construction; all PID, socket and IPC operations
	// stay bound to this service's resolved runtime paths.
	return s.configPath
}

func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var pid int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid); err != nil {
		return 0, err
	}
	return pid, nil
}

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || err == syscall.EPERM
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func defaultCrosslinkDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".crosslink")
	}
	return filepath.Join(home, ".crosslink")
}

func executableName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	return base
}

func defaultPrivilegedDaemonPath(goos, sourcePath string) string {
	if goos == "darwin" {
		return darwinPrivilegedHelperPath
	}
	return sourcePath
}

func defaultServiceLogPath(goos, userPath string) string {
	if goos == "darwin" || goos == "linux" {
		return "/var/log/crosslink.log"
	}
	return userPath
}

var _ = fmt.Sprintf

func (s *Service) socketPath() string {
	return s.runtimePaths.Socket
}

func (s *Service) daemonRunArgs(rootOnly bool) []string {
	args := []string{"-c", s.configPath, "--pid-file", s.pidPath}
	if rootOnly {
		return append(args, "--root-only")
	}
	if s.authorizedUID >= 0 && s.authorizedGID >= 0 {
		args = append(args, "--user-uid", strconv.Itoa(s.authorizedUID), "--user-gid", strconv.Itoa(s.authorizedGID))
	}
	return args
}

func (s *Service) sendCmd(cmd daemonipc.Cmd) (*daemonipc.Response, error) {
	cl := daemonipc.NewClient(s.socketPath())
	return cl.Send(cmd)
}

func socketResult(resp *daemonipc.Response, err error) CommandResult {
	if err != nil {
		return CommandResult{OK: false, Summary: "daemon unreachable: " + err.Error()}
	}
	if !resp.OK {
		return CommandResult{OK: false, Summary: resp.Error}
	}
	return CommandResult{OK: true}
}

func remarshal(src, dst any) {
	b, _ := json.Marshal(src)
	json.Unmarshal(b, dst) //nolint:errcheck
}

// DiscoverCompany calls the daemon to discover company server URL.
func (s *Service) DiscoverCompany(company string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionDiscover, Company: company})
	return socketResult(resp, err)
}

// GetLoginMethods returns available login method names and verify types from the daemon.
func (s *Service) GetLoginMethods() LoginMethodsResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionLoginMethods})
	if err != nil {
		return LoginMethodsResult{OK: false, Error: err.Error()}
	}
	if !resp.OK {
		return LoginMethodsResult{OK: false, Error: resp.Error}
	}
	var info struct {
		Methods     []string `json:"methods"`
		VerifyTypes []string `json:"verify_types"`
	}
	remarshal(resp.Data, &info)
	return LoginMethodsResult{OK: true, Methods: info.Methods, VerifyTypes: info.VerifyTypes}
}

// LoginWithPassword performs password-based login via the daemon.
func (s *Service) LoginWithPassword(account, password string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionLoginPassword, Account: account, Password: password})
	return socketResult(resp, err)
}

// SendVerifyCode sends a verification code via the daemon.
func (s *Service) SendVerifyCode(codeType, account string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionSendCode, CodeType: codeType, Account: account})
	return socketResult(resp, err)
}

// VerifyCode submits a verification code via the daemon.
func (s *Service) VerifyCode(codeType, account, code string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionVerifyCode, CodeType: codeType, Account: account, Code: code})
	return socketResult(resp, err)
}

// GetQRCode fetches QR login URL and token from the daemon.
func (s *Service) GetQRCode() QRCodeResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionGetQRCode})
	if err != nil {
		return QRCodeResult{OK: false, Error: err.Error()}
	}
	if !resp.OK {
		return QRCodeResult{OK: false, Error: resp.Error}
	}
	var dto daemonipc.QRCodeDTO
	remarshal(resp.Data, &dto)
	return QRCodeResult{OK: true, LoginURL: dto.LoginURL, Token: dto.Token}
}

// PollQRStatus polls the daemon for QR login completion.
func (s *Service) PollQRStatus(token string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionPollQR, Token: token})
	return socketResult(resp, err)
}

// Logout logs out via the daemon.
func (s *Service) Logout() CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionLogout})
	return socketResult(resp, err)
}

// CleanupRoutes removes stale capture routes and resets system DNS.
// Safe to call at any time, including when VPN is not connected.
func (s *Service) CleanupRoutes() CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionCleanupRoutes})
	return socketResult(resp, err)
}

func (s *Service) GetProxyGroups() ProxyGroupsResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionListProxyGroups})
	if err == nil && resp.OK {
		var groups []ProxyGroupResult
		remarshal(resp.Data, &groups)
		return ProxyGroupsResult{OK: true, Runtime: true, Groups: groups}
	}
	groups, previewErr := s.previewProxyGroups()
	if previewErr != nil {
		if err != nil {
			return ProxyGroupsResult{OK: false, Error: err.Error()}
		}
		return ProxyGroupsResult{OK: false, Error: resp.Error}
	}
	return ProxyGroupsResult{OK: true, Groups: groups}
}

func (s *Service) previewProxyGroups() ([]ProxyGroupResult, error) {
	cfg, err := config.LoadConfig(s.configPath)
	if err != nil {
		return nil, err
	}
	profilePath, err := cfg.ProxyProfilePath()
	if err != nil {
		return nil, err
	}
	content, err := profile.Read(profilePath)
	if err != nil {
		return nil, err
	}
	previewGroups, err := profile.PreviewGroups(content)
	if err != nil {
		return nil, err
	}
	selections := make(map[string]string)
	statePath, pathErr := cfg.ProxyStatePath()
	if pathErr == nil {
		if stateContent, stateErr := os.ReadFile(statePath); stateErr == nil {
			json.Unmarshal(stateContent, &selections) //nolint:errcheck
		}
	}
	groups := make([]ProxyGroupResult, 0, len(previewGroups))
	for _, previewGroup := range previewGroups {
		selected := previewGroup.Selected
		if stored := selections[previewGroup.Tag]; previewContains(previewGroup, stored) {
			selected = stored
		}
		items := make([]ProxyItemResult, 0, len(previewGroup.Items))
		for _, previewItem := range previewGroup.Items {
			items = append(items, ProxyItemResult{
				Tag: previewItem.Tag, Type: previewItem.Type, DelayMs: previewItem.DelayMs, Selected: previewItem.Tag == selected,
			})
		}
		groups = append(groups, ProxyGroupResult{
			Tag: previewGroup.Tag, Type: previewGroup.Type, Selected: selected, Items: items,
		})
	}
	return groups, nil
}

func previewContains(group profile.PreviewGroup, tag string) bool {
	for _, item := range group.Items {
		if item.Tag == tag {
			return true
		}
	}
	return false
}

func (s *Service) SelectProxy(groupTag, outboundTag string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{
		Action:      daemonipc.ActionSelectProxy,
		GroupTag:    groupTag,
		OutboundTag: outboundTag,
	})
	return socketResult(resp, err)
}

func (s *Service) TestProxyGroup(groupTag string) ProxyDelayResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionTestProxyGroup, GroupTag: groupTag})
	if err != nil {
		return ProxyDelayResult{OK: false, Error: err.Error()}
	}
	if !resp.OK {
		return ProxyDelayResult{OK: false, Error: resp.Error}
	}
	var rawDelays map[string]uint16
	remarshal(resp.Data, &rawDelays)
	delays := make(map[string]int, len(rawDelays))
	for tag, delay := range rawDelays {
		delays[tag] = int(delay)
	}
	return ProxyDelayResult{OK: true, Delays: delays}
}

// Falls back to listing nodes when daemon doesn't support the action yet.
func (s *Service) IsAuthenticated() bool {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionIsAuthenticated})
	if err != nil {
		return false
	}
	// Old daemon returns ok=false with "unknown action" — fall back to node list check.
	if !resp.OK {
		fallback, ferr := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionListNodes})
		return ferr == nil && fallback.OK
	}
	v, _ := resp.Data.(bool)
	return v
}

// ListVPNNodes returns available VPN nodes from the daemon.
func (s *Service) ListVPNNodes() VPNNodesResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionListNodes})
	if err != nil {
		return VPNNodesResult{OK: false, Error: err.Error()}
	}
	if !resp.OK {
		return VPNNodesResult{OK: false, Error: resp.Error}
	}
	var nodes []daemonipc.VPNNodeDTO
	remarshal(resp.Data, &nodes)
	return VPNNodesResult{OK: true, Nodes: nodes}
}

// PingNodes returns VPN nodes with latency measurements.
func (s *Service) PingNodes() VPNNodesResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionPingNodes})
	if err != nil {
		return VPNNodesResult{OK: false, Error: err.Error()}
	}
	if !resp.OK {
		return VPNNodesResult{OK: false, Error: resp.Error}
	}
	var nodes []daemonipc.VPNNodeDTO
	remarshal(resp.Data, &nodes)
	return VPNNodesResult{OK: true, Nodes: nodes}
}

// PingSingleNode pings one VPN node by ID and returns its latency.
func (s *Service) PingSingleNode(nodeID int) VPNNodesResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionPingSingle, NodeID: nodeID})
	if err != nil {
		return VPNNodesResult{OK: false, Error: "daemon unreachable: " + err.Error()}
	}
	if !resp.OK {
		return VPNNodesResult{OK: false, Error: resp.Error}
	}
	var node daemonipc.VPNNodeDTO
	remarshal(resp.Data, &node)
	return VPNNodesResult{OK: true, Nodes: []daemonipc.VPNNodeDTO{node}}
}

// SetFollowSplitRoutes switches between split-tunnel and full-tunnel mode at
// runtime. Takes effect immediately without reconnecting.
func (s *Service) SetFollowSplitRoutes(v bool) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionSetFollowSplitRoutes, FollowSplitRoutes: &v})
	return socketResult(resp, err)
}

// ReloadConfig asks the daemon to reload the saved config and apply supported
// runtime changes.
func (s *Service) ReloadConfig() CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionReloadConfig})
	return socketResult(resp, err)
}

func (s *Service) ConnectOpenVPN(username, password string) OpenVPNStatusResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionOpenVPNConnect, Username: username, Password: password})
	return openVPNStatusResult(resp, err)
}

func (s *Service) DisconnectOpenVPN() OpenVPNStatusResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionOpenVPNDisconnect})
	return openVPNStatusResult(resp, err)
}

func (s *Service) GetOpenVPNStatus() OpenVPNStatusResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionOpenVPNStatus})
	return openVPNStatusResult(resp, err)
}

func (s *Service) PrepareOpenVPNChallenge(challengeID string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionOpenVPNPrepareChallenge, ChallengeID: challengeID})
	return socketResult(resp, err)
}

func (s *Service) CompleteOpenVPNChallenge(challengeID, username, password, secret string) OpenVPNStatusResult {
	resp, err := s.sendCmd(daemonipc.Cmd{
		Action: daemonipc.ActionOpenVPNCompleteChallenge, ChallengeID: challengeID,
		Username: username, Password: password, Secret: secret,
	})
	return openVPNStatusResult(resp, err)
}

func (s *Service) CancelOpenVPNChallenge(challengeID string) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionOpenVPNCancelChallenge, ChallengeID: challengeID})
	return socketResult(resp, err)
}

func openVPNStatusResult(resp *daemonipc.Response, err error) OpenVPNStatusResult {
	if err != nil {
		return OpenVPNStatusResult{OK: false, State: "unavailable", Error: "daemon unreachable: " + err.Error()}
	}
	var status daemonipc.OpenVPNStatusDTO
	remarshal(resp.Data, &status)
	result := OpenVPNStatusResult{
		OK:          resp.OK,
		Configured:  status.Configured,
		Active:      status.Active,
		ProfileName: status.ProfileName,
		State:       status.State,
		Error:       status.Error,
		Server:      status.Server,
		Network:     status.Network,
		Cipher:      status.Cipher,
		IPv4:        append([]string(nil), status.IPv4...),
		IPv6:        append([]string(nil), status.IPv6...),
		DNS:         append([]string(nil), status.DNS...),
		MTU:         status.MTU,
		ConnectedAt: status.ConnectedAt,
		RouteCount:  status.RouteCount,
		DomainCount: status.DomainCount,
	}
	if !resp.OK {
		result.Error = resp.Error
		if result.State == "" {
			result.State = "error"
		}
	}
	if status.Challenge != nil {
		result.Challenge = &OpenVPNChallengeResult{
			ID:            status.Challenge.ID,
			Kind:          status.Challenge.Kind,
			Username:      status.Challenge.Username,
			Message:       status.Challenge.Message,
			URL:           status.Challenge.URL,
			URLAllowed:    status.Challenge.URLAllowed,
			SecretMessage: status.Challenge.SecretMessage,
			Echo:          status.Challenge.Echo,
			PreviousError: status.Challenge.PreviousError,
			Deadline:      status.Challenge.Deadline,
		}
	}
	return result
}

// ConnectVPN starts the unified TUN and the selected CorpLink endpoint.
func (s *Service) ConnectVPN(nodeID int, followSplitRoutes bool) CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionConnect, NodeID: nodeID, FollowSplitRoutes: &followSplitRoutes})
	return socketResult(resp, err)
}

// DisconnectVPN disconnects the active VPN connection via the daemon.
func (s *Service) DisconnectVPN() CommandResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionDisconnect})
	return socketResult(resp, err)
}

// GetVPNStatus returns the current VPN connection status from the daemon.
func (s *Service) GetVPNStatus() VPNStatusResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionStatus})
	if err != nil {
		return VPNStatusResult{OK: false, Error: "daemon unreachable: " + err.Error()}
	}
	if !resp.OK {
		return VPNStatusResult{OK: false, Error: resp.Error}
	}
	var st daemonipc.VPNStatusDTO
	remarshal(resp.Data, &st)
	return VPNStatusResult{
		OK:                            true,
		Connected:                     st.Connected,
		Reconnecting:                  st.Reconnecting,
		ReconnectBackoffTo:            st.ReconnectBackoffTo,
		NodeName:                      st.NodeName,
		VpnIP:                         st.VpnIP,
		DNS:                           st.DNS,
		Protocol:                      st.Protocol,
		ConnectedAt:                   st.ConnectedAt,
		MixedAddr:                     st.MixedAddr,
		RouteModeKnown:                st.RouteModeKnown,
		FollowSplitRoutes:             st.FollowSplitRoutes,
		CorporateRouteCount:           st.CorporateRouteCount,
		CorporateDomainCount:          st.CorporateDomainCount,
		CorporateIgnoredPublicRoutes:  st.CorporateIgnoredPublicRoutes,
		CorporateIgnoredPublicDomains: st.CorporateIgnoredPublicDomains,

		DaemonVersion:        st.DaemonVersion,
		CoreRunning:          st.CoreRunning,
		TUNEnabled:           st.TUNEnabled,
		ProxyAvailable:       st.ProxyAvailable,
		PublicProxyEnabled:   st.PublicProxyEnabled,
		PublicDefault:        st.PublicDefault,
		PublicSelected:       st.PublicSelected,
		PublicSelectedType:   st.PublicSelectedType,
		PublicChain:          st.PublicChain,
		SystemTUNInterface:   st.SystemTUNInterface,
		ExternalTUNs:         st.ExternalTUNs,
		CompatibleTUNs:       st.CompatibleTUNs,
		PublicRouteConflicts: st.PublicRouteConflicts,
		DNSMode:              st.DNSMode,
		DNSServers:           st.DNSServers,
		DNSProtected:         st.DNSProtected,
		DomesticDirect:       st.DomesticDirect,
		DomesticRuleSets:     st.DomesticRuleSets,

		ProbeCycles:              st.ProbeCycles,
		ProbeFailures:            st.ProbeFailures,
		ProbeConsecutive:         st.ProbeConsecutive,
		ProbeThreshold:           st.ProbeThreshold,
		ProbeDNSFlakySkips:       st.ProbeDNSFlakySkips,
		ProbeHostStallSkips:      st.ProbeHostStallSkips,
		ProbeLastAt:              st.ProbeLastAt,
		ProbeLastOutcome:         st.ProbeLastOutcome,
		ProbeTotalCycles:         st.ProbeTotalCycles,
		ProbeTotalFailures:       st.ProbeTotalFailures,
		ProbeTotalDNSFlakySkips:  st.ProbeTotalDNSFlakySkips,
		ProbeTotalHostStallSkips: st.ProbeTotalHostStallSkips,
		ProbeTrafficVetoes:       st.ProbeTrafficVetoes,
		ProbeTotalTrafficVetoes:  st.ProbeTotalTrafficVetoes,
		LastTunnelOKAt:           st.LastTunnelOKAt,
		LastDeadReason:           st.LastDeadReason,
		LastDeadAt:               st.LastDeadAt,
		ReconnectTotal:           st.ReconnectTotal,
		ReconnectLastAt:          st.ReconnectLastAt,
	}
}

// GetVPNStats returns cumulative WireGuard byte counters from the daemon.
func (s *Service) GetVPNStats() VPNStatsResult {
	resp, err := s.sendCmd(daemonipc.Cmd{Action: daemonipc.ActionGetStats})
	if err != nil {
		return VPNStatsResult{OK: false}
	}
	if !resp.OK {
		return VPNStatsResult{OK: false}
	}
	var st daemonipc.VPNStatsDTO
	remarshal(resp.Data, &st)
	return VPNStatsResult{OK: true, TxBytes: st.TxBytes, RxBytes: st.RxBytes}
}
