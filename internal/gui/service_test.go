package gui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/limauriga-ux/crosslink/internal/config"
	"github.com/limauriga-ux/crosslink/internal/profile"
)

type fakeRunner struct {
	calls   []RunRequest
	next    RunResult
	results []RunResult
	after   func(req RunRequest)
}

func (r *fakeRunner) Run(ctx context.Context, req RunRequest) RunResult {
	r.calls = append(r.calls, req)
	if r.after != nil {
		defer r.after(req)
	}
	if len(r.results) > 0 {
		res := r.results[0]
		r.results = r.results[1:]
		return res
	}
	if r.next == (RunResult{}) {
		return RunResult{OK: true}
	}
	return r.next
}

func TestDaemonCommandsUseConfiguredBinaryAndConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &fakeRunner{next: RunResult{OK: true, Stdout: "daemon started (pid 1234)\n"}}
	svc := NewService(Options{
		DaemonPath: "/tmp/crosslink-daemon",
		ConfigPath: "/tmp/config.json",
		Runner:     runner,
	})
	runner.after = func(req RunRequest) {
		if strings.Contains(strings.Join(req.Args, " "), "/tmp/config.json") {
			_ = os.MkdirAll(filepath.Dir(svc.pidPath), 0755)
			_ = os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
		}
	}

	if res := svc.StartDaemon(""); !res.OK {
		t.Fatalf("StartDaemon OK = false: %+v", res)
	}
	if res := svc.StopDaemon(); !res.OK {
		t.Fatalf("StopDaemon OK = false: %+v", res)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %d, want 2", len(runner.calls))
	}
	if runtime.GOOS == "darwin" {
		if runner.calls[0].Path != "osascript" {
			t.Fatalf("start path = %q, want osascript", runner.calls[0].Path)
		}
		if got := strings.Join(runner.calls[0].Args, " "); !strings.Contains(got, darwinPrivilegedHelperPath) || strings.Contains(got, " start ") || !strings.Contains(got, "/tmp/config.json") || !strings.Contains(got, "--user-uid") || !strings.Contains(got, "administrator privileges") {
			t.Fatalf("start args = %q, want privileged managed helper", got)
		}
		if runner.calls[1].Path != "osascript" {
			t.Fatalf("stop path = %q, want osascript", runner.calls[1].Path)
		}
		if got := strings.Join(runner.calls[1].Args, " "); !strings.Contains(got, darwinPrivilegedHelperPath) || !strings.Contains(got, "stop") || !strings.Contains(got, "administrator privileges") {
			t.Fatalf("stop args = %q, want privileged daemon stop", got)
		}
		return
	}
	if got := strings.Join(runner.calls[0].Args, " "); !strings.Contains(got, "-c /tmp/config.json --pid-file ") || strings.Contains(got, "start") {
		t.Fatalf("start args = %q", got)
	}
	if got := strings.Join(runner.calls[1].Args, " "); !strings.Contains(got, "stop -c /tmp/config.json --pid-file ") {
		t.Fatalf("stop args = %q", got)
	}
	if runner.calls[0].Path != "/tmp/crosslink-daemon" {
		t.Fatalf("daemon path = %q", runner.calls[0].Path)
	}
}

func TestNewServiceSeparatesStagingAndPrivilegedDaemonPaths(t *testing.T) {
	svc := NewService(Options{Runner: &fakeRunner{}})
	if !strings.Contains(svc.configPath, filepath.Join(".crosslink", "config.json")) {
		t.Fatalf("config path = %q, want ~/.crosslink/config.json", svc.configPath)
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		if svc.logPath != "/var/log/crosslink.log" {
			t.Fatalf("privileged log path = %q", svc.logPath)
		}
	} else if !strings.Contains(svc.logPath, filepath.Join(".crosslink", "crosslink.log")) {
		t.Fatalf("log path = %q", svc.logPath)
	}
	if !strings.Contains(svc.daemonSourcePath, filepath.Join(".crosslink", "bin", "crosslink-daemon")) {
		t.Fatalf("daemon staging path = %q", svc.daemonSourcePath)
	}
	if runtime.GOOS == "darwin" && svc.daemonPath != darwinPrivilegedHelperPath {
		t.Fatalf("privileged daemon path = %q", svc.daemonPath)
	}
}

func TestCommandResultPrefersCommandOutputOverGenericExitStatus(t *testing.T) {
	res := commandResult(RunResult{
		OK:       false,
		Stderr:   "read config /missing/config.json: no such file or directory\n",
		Error:    "exit status 1",
		ExitCode: 1,
	})

	if res.OK {
		t.Fatal("commandResult OK = true, want false")
	}
	if res.Summary != "read config /missing/config.json: no such file or directory" {
		t.Fatalf("summary = %q", res.Summary)
	}
	if !strings.Contains(res.Details, "stderr:") || !strings.Contains(res.Details, "exit code: 1") || !strings.Contains(res.Details, "error: exit status 1") {
		t.Fatalf("details = %q, want stderr, exit code, and exec error", res.Details)
	}
}

func TestStartDaemonReturnsSuccessWhenStatusIsAlreadyRunning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &fakeRunner{}
	svc := NewService(Options{DaemonPath: "/tmp/crosslink-daemon", ConfigPath: "/tmp/config.json", Runner: runner})
	if err := os.MkdirAll(filepath.Dir(svc.pidPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	res := svc.StartDaemon("")
	if !res.OK {
		t.Fatalf("StartDaemon = %+v, want OK", res)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner calls = %d, want pidfile status only", len(runner.calls))
	}
	if !strings.Contains(res.Summary, "daemon running") {
		t.Fatalf("summary = %q, want daemon running", res.Summary)
	}
}

func TestStartDaemonTreatsAlreadyRunningCommandErrorAsRunningStatus(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	runner := &fakeRunner{
		results: []RunResult{
			{OK: false, Stderr: "daemon already running (pid 1234)\n", Error: "exit status 1", ExitCode: 1},
		},
	}
	svc := NewService(Options{DaemonPath: "/tmp/crosslink-daemon", ConfigPath: "/tmp/config.json", Runner: runner})
	runner.after = func(req RunRequest) {
		_ = os.MkdirAll(filepath.Dir(svc.pidPath), 0755)
		_ = os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
	}

	res := svc.StartDaemon("")
	if !res.OK {
		t.Fatalf("StartDaemon = %+v, want OK", res)
	}
	if !strings.Contains(res.Summary, "daemon running") {
		t.Fatalf("summary = %q, want daemon running", res.Summary)
	}
}

func TestStartDaemonFailsWhenDaemonNeverBecomesRunning(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	runner := &fakeRunner{
		results: []RunResult{
			{OK: true, Stdout: "daemon started (pid 1234)\n"},
		},
	}
	svc := NewService(Options{DaemonPath: "/tmp/crosslink-daemon", ConfigPath: configPath, Runner: runner})
	res := svc.StartDaemon("")
	if res.OK {
		t.Fatalf("StartDaemon = %+v, want failure", res)
	}
	if !strings.Contains(res.Summary, "did not become running") {
		t.Fatalf("summary = %q, want did not become running", res.Summary)
	}
}

func TestGetDaemonStatusReadsPidFileDirectly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	runner := &fakeRunner{next: RunResult{Stdout: "daemon not running\n"}}
	svc := NewService(Options{DaemonPath: "/tmp/crosslink-daemon", Runner: runner})
	if err := os.MkdirAll(filepath.Dir(svc.pidPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	status := svc.GetDaemonStatus()
	if status.State != "running" || status.PID != os.Getpid() {
		t.Fatalf("status = %+v, want current process running", status)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner calls = %d, want pidfile status without CLI", len(runner.calls))
	}
}

func TestLoadSaveAndValidateConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"core":{"mixed_port":1080}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewService(Options{ConfigPath: path, Runner: &fakeRunner{}})

	doc := svc.LoadConfig("")
	if !doc.OK || doc.Config == nil || doc.Config.Core.MixedPort != 1080 {
		t.Fatalf("LoadConfig = %+v", doc)
	}
	doc.Config.Core.LogLevel = "debug"
	res := svc.SaveConfig("", doc.Config)
	if !res.OK {
		t.Fatalf("SaveConfig = %+v", res)
	}
	reloaded := svc.LoadConfig("")
	if reloaded.Config.Core.LogLevel != "debug" {
		t.Fatalf("core log level after reload = %q", reloaded.Config.Core.LogLevel)
	}
}

func TestLoadConfigCreatesSecureDefaultWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	svc := NewService(Options{ConfigPath: path, Runner: &fakeRunner{}})

	doc := svc.LoadConfig("")
	if !doc.OK || doc.Config == nil {
		t.Fatalf("LoadConfig = %+v", doc)
	}
	if !doc.Config.Core.TUNEnabled || doc.Config.Corplink.InsecureSkipVerify {
		t.Fatalf("insecure default config = %+v", doc.Config)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("default config was not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestSaveConfigRollsBackWhenCoreReloadFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, ".crosslink", "config.json")
	svc := NewService(Options{ConfigPath: configPath, Runner: &fakeRunner{}})

	previousConfig := config.DefaultConfig()
	previousConfig.Core.DomesticDirect = false
	if result := svc.SaveConfig("", previousConfig); !result.OK {
		t.Fatalf("initial SaveConfig = %+v", result)
	}
	previous, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	updated := *previousConfig
	updated.Core.LogLevel = "debug"
	result := svc.SaveConfig("", &updated)
	if result.OK {
		t.Fatal("config update unexpectedly succeeded without daemon IPC")
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(previous) {
		t.Fatalf("config after failed reload = %s, want %s", restored, previous)
	}
}

func TestStartDaemonCreatesUserWritableConfigBeforePrivilegeEscalation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".crosslink", "config.json")
	runner := &fakeRunner{next: RunResult{OK: true, Stdout: "daemon started (pid 1234)\n"}}
	svc := NewService(Options{
		DaemonPath: "/tmp/crosslink-daemon",
		ConfigPath: path,
		Runner:     runner,
	})
	runner.after = func(req RunRequest) {
		_ = os.MkdirAll(filepath.Dir(svc.pidPath), 0755)
		_ = os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
	}

	res := svc.StartDaemon("")
	if !res.OK {
		t.Fatalf("StartDaemon = %+v, want OK", res)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config was not created before daemon start: %v", err)
	}
	doc := svc.LoadConfig("")
	if !doc.OK {
		t.Fatalf("LoadConfig after start = %+v", doc)
	}
}

func TestSaveProxyProfileRollsBackWhenCoreReloadFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, ".crosslink", "config.json")
	profilePath := filepath.Join(home, ".crosslink", "proxy.json")
	svc := NewService(Options{ConfigPath: configPath, Runner: &fakeRunner{}})
	cfg := config.DefaultConfig()
	cfg.Core.Profile = profilePath
	if result := svc.SaveConfig("", cfg); !result.OK {
		t.Fatalf("SaveConfig = %+v", result)
	}
	previous := []byte(`{"outbounds":[{"type":"direct","tag":"old"}],"route":{"final":"old"}}`)
	if err := os.WriteFile(profilePath, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result := svc.SaveProxyProfile(`{"outbounds":[{"type":"direct","tag":"new"}],"route":{"final":"new"}}`)
	if result.OK {
		t.Fatal("profile update unexpectedly succeeded without a daemon IPC server")
	}
	restored, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(previous) {
		t.Fatalf("profile after rollback = %q, want %q", restored, previous)
	}
}

func TestGetProxyGroupsFallsBackToProfilePreview(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, ".crosslink", "config.json")
	profilePath := filepath.Join(home, ".crosslink", "proxy.json")
	statePath := filepath.Join(home, ".crosslink", "proxy-state.json")
	svc := NewService(Options{ConfigPath: configPath, Runner: &fakeRunner{}})
	cfg := config.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.StateFile = statePath
	if result := svc.SaveConfig("", cfg); !result.OK {
		t.Fatalf("SaveConfig = %+v", result)
	}
	profileContent := []byte(`{"outbounds":[{"type":"direct","tag":"edge-a"},{"type":"direct","tag":"edge-b"},{"type":"selector","tag":"Proxy","outbounds":["edge-a","edge-b"],"default":"edge-a"}]}`)
	if err := os.WriteFile(profilePath, profileContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(`{"Proxy":"edge-b"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	result := svc.GetProxyGroups()
	if !result.OK || result.Runtime || len(result.Groups) != 1 {
		t.Fatalf("GetProxyGroups = %+v", result)
	}
	if result.Groups[0].Selected != "edge-b" || !result.Groups[0].Items[1].Selected {
		t.Fatalf("preview selection = %+v", result.Groups[0])
	}
}

func TestRulePlanResultUsesEmptyArraysInsteadOfNull(t *testing.T) {
	result := rulePlanResult("rules.json", profile.RulePlan{}, profile.RuleContext{})
	content, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, `"prepend":[]`) || !strings.Contains(text, `"append":[]`) || strings.Contains(text, `"prepend":null`) || strings.Contains(text, `"append":null`) {
		t.Fatalf("rule plan JSON = %s", text)
	}
}

func TestRulePlanPersistsOutsideSubscriptionAndValidatesTargets(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configPath := filepath.Join(home, ".crosslink", "config.json")
	profilePath := filepath.Join(home, ".crosslink", "proxy.json")
	rulesPath := filepath.Join(home, ".crosslink", "rules.json")
	svc := NewService(Options{ConfigPath: configPath, Runner: &fakeRunner{}})
	cfg := config.DefaultConfig()
	cfg.Core.Profile = profilePath
	cfg.Core.Rules = rulesPath
	if result := svc.SaveConfig("", cfg); !result.OK {
		t.Fatalf("SaveConfig = %+v", result)
	}
	profileContent := []byte(`{
		"outbounds":[{"type":"direct","tag":"edge"},{"type":"selector","tag":"Proxy","outbounds":["edge"]}],
		"route":{"rules":[{"domain":["profile.example"],"action":"route","outbound":"Proxy"}],"final":"Proxy"}
	}`)
	if err := os.WriteFile(profilePath, profileContent, 0o600); err != nil {
		t.Fatal(err)
	}

	result := svc.SaveRulePlan(
		[]string{"DOMAIN-SUFFIX,local.example,Proxy"},
		[]string{"IP-CIDR,10.20.0.0/16,CORP"},
	)
	if !result.OK || result.ProfileRuleCount != 1 || len(result.Targets) < 5 {
		t.Fatalf("SaveRulePlan = %+v", result)
	}
	saved, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "local.example") || strings.Contains(string(saved), "profile.example") {
		t.Fatalf("independent rule plan = %s", saved)
	}

	invalid := svc.SaveRulePlan([]string{"DOMAIN,broken.example,Missing"}, nil)
	if invalid.OK || !strings.Contains(invalid.Error, "unavailable") {
		t.Fatalf("invalid SaveRulePlan = %+v", invalid)
	}
	unchanged, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(saved) {
		t.Fatalf("invalid save changed plan: %s", unchanged)
	}
}

func TestExecRunnerHonorsTimeout(t *testing.T) {
	runner := ExecRunner{Timeout: 20 * time.Millisecond}
	res := runner.Run(context.Background(), RunRequest{
		Path: "sh",
		Args: []string{"-c", "sleep 1"},
	})
	if res.OK || !res.TimedOut {
		t.Fatalf("Run = %+v, want timeout", res)
	}
}
