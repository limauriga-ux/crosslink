package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/limauriga-ux/crosslink/internal/config"
	vpnpkg "github.com/limauriga-ux/crosslink/internal/core"
	"github.com/limauriga-ux/crosslink/internal/corplink"
	"github.com/limauriga-ux/crosslink/internal/daemon"
	"github.com/limauriga-ux/crosslink/internal/daemonipc"
	"github.com/limauriga-ux/crosslink/internal/netroute"
	"github.com/limauriga-ux/crosslink/internal/openvpnprofile"
	"github.com/limauriga-ux/crosslink/internal/outbound"
	"github.com/limauriga-ux/crosslink/internal/wgdevice"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Version is injected at build time via -ldflags "-X main.Version=x.y.z".
// Without this declaration the linker flag the build already passes was
// silently discarded, which left every daemon log indistinguishable between
// releases — the exact thing that made a recent field diagnosis slower than it
// needed to be.
var Version = "dev"

var configPath = flag.String("c", "", "config file path")
var pidFilePathFlag = flag.String("pid-file", "", "pid file path")
var authorizedUIDFlag = flag.Int("user-uid", -1, "desktop user UID authorized for IPC and managed files")
var authorizedGIDFlag = flag.Int("user-gid", -1, "desktop user GID authorized for managed files")
var rootOnlyFlag = flag.Bool("root-only", false, "run as a root-owned system daemon without a desktop user")
var cleanupRoutesAndDNS = cleanupPersistedRoutes
var activeConnection connectionSupervisor

// reconnectMetrics counts auto-reconnect activity for the daemon's lifetime, so
// "how often is this flapping?" is answerable over IPC instead of only by
// grepping a root-owned log.
var reconnectMetrics struct {
	total     atomic.Int64
	lastUnix  atomic.Int64
	backoffTo atomic.Int64 // unix time the current backoff expires; 0 when not backing off
}

func main() {
	if isWindowsService() {
		flag.Parse()
		if err := runService(); err != nil {
			log.Printf("[main] service fatal: %v", err)
			os.Exit(1)
		}
		return
	}

	// Already running as the daemon child — execute directly. This must happen
	// before subcommand dispatch because the parent may have been invoked as
	// "crosslink-daemon -c config.json".
	if os.Getenv("CROSSLINK_DAEMON") == "1" {
		flag.Parse()
		if err := run(); err != nil {
			log.Printf("[main] fatal: %v", err)
			os.Exit(1)
		}
		return
	}

	// Subcommand dispatch (before flag.Parse)
	if cmd := daemonCommandFromArgs(os.Args); cmd != "" {
		switch cmd {
		case "stop":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStop()
			return
		case "restart":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStop()
			doStart()
			return
		case "status":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStatus()
			return
		case "start":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			doStart()
			return
		case "install-service":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			paths, err := daemonRuntimePaths()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if err := ensureAdmin(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if err := validateDaemonRuntime(paths); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if err := installService(paths.ConfigPath, paths.PIDFile, *authorizedUIDFlag, *authorizedGIDFlag, *rootOnlyFlag); err != nil {
				fmt.Fprintf(os.Stderr, "install service: %v\n", err)
				os.Exit(1)
			}
			return
		case "uninstall-service":
			flag.CommandLine.Parse(os.Args[2:]) //nolint:errcheck
			if err := ensureAdmin(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			if err := uninstallService(); err != nil {
				fmt.Fprintf(os.Stderr, "uninstall service: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	flag.Parse()

	// Parent process: escalate if needed, then fork daemon child.
	doStart()
}

func daemonCommandFromArgs(args []string) string {
	if len(args) <= 1 || strings.HasPrefix(args[1], "-") {
		return ""
	}
	switch args[1] {
	case "start", "stop", "restart", "status", "install-service", "uninstall-service":
		return args[1]
	default:
		return ""
	}
}

// doStart escalates privileges if needed, then detaches the daemon child.
func doStart() {
	if err := ensureAdmin(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	paths, err := daemonRuntimePaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := validateDaemonRuntime(paths); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if pid, _ := daemon.ReadPidFile(paths.PIDFile); pid > 0 && daemon.IsRunning(pid) {
		fmt.Fprintf(os.Stderr, "daemon already running (pid %d)\n", pid)
		os.Exit(1)
	}
	if err := daemon.RemovePidFile(paths.PIDFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "remove stale pid file: %v\n", err)
		os.Exit(1)
	}

	pid, err := daemon.Detach(daemonArgs(os.Args))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start daemon: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("daemon started (pid %d)\n", pid)
}

func daemonArgs(args []string) []string {
	if len(args) > 1 && (args[1] == "start" || args[1] == "restart") {
		out := make([]string, 0, len(args)-1)
		out = append(out, args[0])
		out = append(out, args[2:]...)
		return out
	}
	out := make([]string, len(args))
	copy(out, args)
	return out
}

func doStop() {
	paths, err := daemonRuntimePaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	if err := validateDaemonRuntime(paths); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	if err := netroute.ConfigureHostRouteState(paths.HostRouteState); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	pid, err := daemon.ReadPidFile(paths.PIDFile)
	if err != nil || !daemon.IsRunning(pid) {
		fmt.Println("daemon not running")
		daemon.RemovePidFile(paths.PIDFile) //nolint:errcheck
		cleanupPersistedRoutes()
		return
	}
	shutdownErr := requestDaemonShutdown(paths.Socket)
	if shutdownErr == nil {
		if waitErr := waitForProcessExit(pid, daemonStopWaitTimeout, 100*time.Millisecond, daemon.IsRunning); waitErr == nil {
			cleanupPersistedRoutes()
			daemon.RemovePidFile(paths.PIDFile) //nolint:errcheck
			fmt.Printf("daemon stopped (pid %d)\n", pid)
			return
		} else if !*rootOnlyFlag {
			fmt.Fprintf(os.Stderr, "daemon acknowledged shutdown but pid file did not clear safely: %v\n", waitErr)
			return
		}
	} else if !*rootOnlyFlag {
		// The desktop user owns the managed PID file and can replace it. Never
		// turn an unauthenticated PID into a root signal when IPC did not prove
		// that the target is the CrossLink daemon.
		fmt.Fprintf(os.Stderr, "failed to request authenticated daemon shutdown: %v\n", shutdownErr)
		return
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find root-only daemon %d: %v\n", pid, err)
		return
	}
	if err := signalProcessStop(process); err != nil {
		fmt.Fprintf(os.Stderr, "failed to signal root-only daemon %d: %v\n", pid, err)
		return
	}
	if err := waitForProcessExit(pid, 10*time.Second, 100*time.Millisecond, daemon.IsRunning); err != nil {
		fmt.Fprintf(os.Stderr, "failed to stop root-only daemon cleanly: %v\n", err)
		return
	}
	cleanupPersistedRoutes()
	daemon.RemovePidFile(paths.PIDFile) //nolint:errcheck
	fmt.Printf("daemon stopped (pid %d)\n", pid)
}

func requestDaemonShutdown(socketPath string) error {
	cl := daemonipc.NewClient(socketPath)
	resp, err := cl.Send(daemonipc.Cmd{Action: daemonipc.ActionShutdown})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}

func waitForProcessExit(pid int, timeout, interval time.Duration, isRunning func(int) bool) error {
	deadline := time.Now().Add(timeout)
	for {
		if !isRunning(pid) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("daemon %d did not exit within %s", pid, timeout)
		}
		time.Sleep(interval)
	}
}

func cleanupPersistedRoutes() {
	if err := netroute.CleanupPersistedHostRoutes(); err != nil {
		log.Printf("[route] cleanup persisted host routes: %v", err)
	}
}

// cleanupStaleRoutesAtStartup is the lighter-touch variant used on daemon
// boot. It keeps host routes whose recorded gateway still matches the
// current physical default gateway (so a daemon restart on the same
// network doesn't churn good routes), and only deletes the ones whose
// recorded gateway no longer matches — exactly the routes that surface as
// `connect: can't assign requested address` after roaming.
func cleanupStaleRoutesAtStartup() {
	if err := netroute.CleanupStalePersistedHostRoutes(); err != nil {
		log.Printf("[route] startup persisted-route cleanup: %v", err)
	}
	// Catch orphaned host routes whose recorded state file was lost.
	scanAndDeleteStaleKernelHostRoutes()
}

func scanAndDeleteStaleKernelHostRoutes() {
	if err := netroute.ScanAndDeleteStaleKernelHostRoutes(); err != nil {
		log.Printf("[route] stale kernel host-route scan: %v", err)
	}
}

func cleanupAfterReconnectDisconnect(preserved bool) {
	if preserved {
		return
	}
	cleanupRoutesAndDNS()
}

func doStatus() {
	paths, err := daemonRuntimePaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	if err := validateDaemonRuntime(paths); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	pid, err := daemon.ReadPidFile(paths.PIDFile)
	if err != nil || !daemon.IsRunning(pid) {
		fmt.Println("daemon not running")
		return
	}
	fmt.Printf("daemon running (pid %d)\n", pid)
}

func daemonRuntimePaths() (config.DaemonRuntimePaths, error) {
	return config.ResolveDaemonRuntimePaths(*configPath, *pidFilePathFlag)
}

func validateDaemonRuntime(paths config.DaemonRuntimePaths) error {
	_, err := config.ValidateDaemonDataRoot(paths, *authorizedUIDFlag, *authorizedGIDFlag, *rootOnlyFlag)
	return err
}

func daemonOwnerIDs(cfg *config.Config) (uid, gid int) {
	if owner, ok := cfg.DaemonOwner(); ok {
		return owner.UID, owner.GID
	}
	return *authorizedUIDFlag, *authorizedGIDFlag
}

func run() error {
	return runWithContext(context.Background())
}

func runWithContext(ctx context.Context) error {
	paths, err := daemonRuntimePaths()
	if err != nil {
		return err
	}
	cfg, err := config.LoadDaemonConfig(paths.ConfigPath, *authorizedUIDFlag, *authorizedGIDFlag, *rootOnlyFlag)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load config: %s does not exist; start from the GUI once so it can create the managed config", paths.ConfigPath)
		}
		return fmt.Errorf("load config: %w", err)
	}
	if err := netroute.ConfigureHostRouteState(paths.HostRouteState); err != nil {
		return fmt.Errorf("configure route state: %w", err)
	}
	setupLogging(cfg)
	log.Printf("[main] crosslink daemon starting, version: %s, pid: %d", Version, os.Getpid())

	uid, gid := daemonOwnerIDs(cfg)
	if err := daemon.WritePidFileOwned(paths.PIDFile, os.Getpid(), uid, gid); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}
	defer daemon.RemovePidFile(paths.PIDFile) //nolint:errcheck

	prepareCorplinkConfig(cfg)
	configState := newDaemonConfigState(cfg, paths.ConfigPath)
	corplinkMgr := corplink.NewManagerWithConfig(paths.Session, cfg.Corplink)
	vpnMgr := vpnpkg.New(cfg)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sockPath := paths.Socket
	uid, gid = daemonOwnerIDs(cfg)
	sockSrv := daemonipc.NewServerWithAuthorizedOwner(sockPath, uid, gid, buildHandler(configState, corplinkMgr, vpnMgr, cancel))
	if err := sockSrv.Start(); err != nil {
		return fmt.Errorf("socket server: %w", err)
	}
	if err := vpnMgr.Start(); err != nil {
		// Keep IPC alive so the GUI can replace a malformed Profile and ask the
		// manager to reload it without requiring manual daemon repair.
		log.Printf("[core] startup failed: %v", err)
	}

	shutdownCh := make(chan os.Signal, 2)
	signal.Notify(shutdownCh, shutdownSigs...)
	defer signal.Stop(shutdownCh)

	// An empty variadic signal.Notify call subscribes to every signal, so keep
	// the reload registration conditional on platforms that define reloadSigs.
	var reloadCh chan os.Signal
	if len(reloadSigs) > 0 {
		reloadCh = make(chan os.Signal, 1)
		signal.Notify(reloadCh, reloadSigs...)
		defer signal.Stop(reloadCh)
	}

	log.Printf("[main] daemon socket listening: %s", sockPath)

	// Do slow network cleanup after the IPC socket is ready, so the GUI can
	// observe daemon status even if macOS route/DNS commands stall. We only
	// drop *stale* host routes here — entries whose recorded gateway no
	// longer matches the current default gateway — so a same-network
	// restart preserves still-valid routes and keeps the corplink server
	// reachable.
	go func() {
		log.Printf("[main] startup cleanup begin")
		cleanupStaleRoutesAtStartup()
		log.Printf("[main] startup cleanup done")
	}()

	return waitForDaemonShutdown(
		ctx,
		shutdownCh,
		reloadCh,
		daemonShutdownTimeout,
		func(enterStep func(string)) {
			// Stop accepting privileged IPC before dismantling lifecycle state;
			// wait for already-running handlers only after Disconnect has had a
			// chance to release their dependencies.
			enterStep(shutdownStepStopAccepting)
			sockSrv.StopAccepting()
			enterStep(shutdownStepBackground)
			cancel()
			activeConnection.Stop()
			enterStep(shutdownStepVPNDisconnect)
			if err := vpnMgr.Disconnect(); err != nil {
				log.Printf("[main] disconnect during shutdown: %v", err)
			}
			enterStep(shutdownStepIPCWait)
			sockSrv.Wait()
		},
		func(sig os.Signal) {
			log.Printf("[main] received %v; config reload is available only over IPC, ignoring", sig)
		},
	)
}

func prepareCorplinkConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	cfg.Corplink.DirectInterface = cfg.DirectOutbound.Interface
	cfg.Corplink.PublicDNS = config.BootstrapDNSServers()
}

type daemonConfigState struct {
	configPath  string
	operationMu sync.RWMutex
	current     atomic.Pointer[config.Config]
}

func newDaemonConfigState(cfg *config.Config, configPath string) *daemonConfigState {
	state := &daemonConfigState{configPath: configPath}
	state.current.Store(cfg)
	return state
}

func (s *daemonConfigState) Load() *config.Config {
	return s.current.Load()
}

func (s *daemonConfigState) Store(cfg *config.Config) {
	s.current.Store(cfg)
}

func buildHandler(configState *daemonConfigState, cm *corplink.Manager, vm *vpnpkg.Manager, shutdown func()) daemonipc.Handler {
	return func(cmd daemonipc.Cmd) daemonipc.Response {
		ctx := context.Background()
		cl := cm.Client()
		log.Printf("[ipc] action=%s", cmd.Action)
		// Reload, logout, and managed-profile deletion mutate lifecycle or
		// filesystem state that every other handler assumes is stable.
		exclusive := cmd.Action == daemonipc.ActionReloadConfig || cmd.Action == daemonipc.ActionLogout || cmd.Action == daemonipc.ActionOpenVPNRemoveProfile
		if exclusive {
			configState.operationMu.Lock()
			defer configState.operationMu.Unlock()
		} else {
			configState.operationMu.RLock()
			defer configState.operationMu.RUnlock()
		}
		return dispatchHandler(ctx, cmd, cl, cm, vm, configState, shutdown)
	}
}

func dispatchHandler(ctx context.Context, cmd daemonipc.Cmd, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, configState *daemonConfigState, shutdown func()) daemonipc.Response {
	cfg := configState.Load()
	switch cmd.Action {
	case daemonipc.ActionShutdown:
		if shutdown != nil {
			go shutdown()
		}
		return daemonipc.Response{OK: true}
	case daemonipc.ActionDiscover:
		if err := cl.DiscoverCompany(ctx, cmd.Company); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionLoginMethods:
		info, err := cl.LoginMethods(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: info}

	case daemonipc.ActionSendCode:
		if err := cl.SendCode(ctx, cmd.CodeType, cmd.Account); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionVerifyCode:
		if err := cl.VerifyCode(ctx, cmd.CodeType, cmd.Account, cmd.Code); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionLoginPassword:
		if err := cl.LoginWithPassword(ctx, cmd.Account, cmd.Password); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionGetQRCode:
		qr, err := cl.GetQRCode(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: daemonipc.QRCodeDTO{
			LoginURL: qr.LoginURL, Token: qr.Token,
		}}

	case daemonipc.ActionPollQR:
		if err := cl.PollQRLogin(ctx, cmd.Token); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionLogout:
		// Serialized by the exclusive lock: a racing connect must not rebuild
		// a tunnel from credentials erased here. Stop the supervisor first
		// so keepalive/report loops cannot outlive the session, then sever
		// the corporate generation while keeping the public core (and any
		// OpenVPN endpoint) alive — an account switch must not black-hole the
		// machine. Credentials are cleared last and saved.
		activeConnection.Stop()
		if _, err := vm.DisconnectForReconnect(); err != nil {
			log.Printf("[ipc] logout corp disconnect: %v", err)
		}
		vm.SetReconnecting(false)
		reconnectMetrics.backoffTo.Store(0)
		cl.Logout(ctx)
		cm.Session().Save() //nolint:errcheck
		return daemonipc.Response{OK: true}

	case daemonipc.ActionCleanupRoutes:
		cleanupPersistedRoutes()
		// Also scrub orphaned kernel host routes whose next-hop gateway is
		// no longer on a connected subnet after Wi-Fi roaming.
		scanAndDeleteStaleKernelHostRoutes()
		log.Printf("[ipc] cleanup_routes: done")
		return daemonipc.Response{OK: true}

	case daemonipc.ActionListNodes:
		// CorpLink auth server IP (the host this call dials) sits in our
		// persisted host-routes.json — if user roamed networks while
		// disconnected the route's gateway is stale and dial returns
		// EADDRNOTAVAIL before we even leave the kernel. Scan first.
		scanAndDeleteStaleKernelHostRoutes()
		prepareCorplinkControlPath(ctx, cl, cfg)
		nodes, err := cl.ListNodes(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		dtos := make([]daemonipc.VPNNodeDTO, len(nodes))
		for i, n := range nodes {
			dtos[i] = daemonipc.VPNNodeDTO{
				ID: n.ID, Name: n.Name,
				ProtocolMode: n.ProtocolMode,
			}
		}
		return daemonipc.Response{OK: true, Data: dtos}

	case daemonipc.ActionPingNodes:
		// Pre-flight scan covers two failure modes: the auth-server dial
		// in cl.ListNodes (would block the whole call), and each node's
		// per-IP host route (would make every node look dead at 9999 ms).
		scanAndDeleteStaleKernelHostRoutes()
		prepareCorplinkControlPath(ctx, cl, cfg)
		nodes, err := cl.ListNodes(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		dtos := make([]daemonipc.VPNNodeDTO, len(nodes))
		var wg sync.WaitGroup
		for i, n := range nodes {
			wg.Add(1)
			go func(idx int, node corplink.VPNNode) {
				defer wg.Done()
				lat, err := cl.PingNode(ctx, node)
				if err != nil {
					log.Printf("[ping] node=%s ip=%s apiPort=%d err=%v", node.Name, node.IP, node.APIPort, err)
				}
				dtos[idx] = daemonipc.VPNNodeDTO{
					ID: node.ID, Name: node.Name,
					LatencyMs: lat, ProtocolMode: node.ProtocolMode,
				}
			}(i, n)
		}
		wg.Wait()
		return daemonipc.Response{OK: true, Data: dtos}

	case daemonipc.ActionPingSingle:
		scanAndDeleteStaleKernelHostRoutes()
		prepareCorplinkControlPath(ctx, cl, cfg)
		nodes, err := cl.ListNodes(ctx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: "list nodes: " + err.Error()}
		}
		for _, n := range nodes {
			if n.ID == cmd.NodeID {
				lat, _ := cl.PingNode(ctx, n)
				return daemonipc.Response{OK: true, Data: daemonipc.VPNNodeDTO{
					ID: n.ID, Name: n.Name,
					LatencyMs: lat, ProtocolMode: n.ProtocolMode,
				}}
			}
		}
		return daemonipc.Response{OK: false, Error: fmt.Sprintf("node %d not found", cmd.NodeID)}

	case daemonipc.ActionOpenVPNRemoveProfile:
		// This action holds operationMu exclusively, so a concurrent connect
		// either finishes first (and Active rejects the deletion) or waits
		// until the profile has been removed and then fails to load it.
		if vm.OpenVPNStatus().Active {
			return daemonipc.Response{OK: false, Error: "OpenVPN is connecting or connected; disconnect it before removing the profile"}
		}
		dataDir, profilePath, err := cfg.OpenVPNProfilePath()
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		if err := openvpnprofile.RemoveManaged(dataDir, profilePath); err != nil {
			return daemonipc.Response{OK: false, Error: "remove OpenVPN profile: " + err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionOpenVPNConnect:
		dataDir, profilePath, err := cfg.OpenVPNProfilePath()
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		managed, err := openvpnprofile.LoadManaged(dataDir, profilePath)
		if err != nil {
			return daemonipc.Response{OK: false, Error: "load OpenVPN profile: " + err.Error()}
		}
		if err := vm.ConnectOpenVPN(managed, cmd.Username, cmd.Password); err != nil {
			status, statusErr := daemonOpenVPNStatus(cfg, vm)
			if statusErr != nil {
				return daemonipc.Response{OK: false, Error: err.Error() + "; read recovery status: " + statusErr.Error()}
			}
			return daemonipc.Response{OK: false, Error: err.Error(), Data: status}
		}
		status := vm.WaitOpenVPNState(2 * time.Second)
		return daemonipc.Response{OK: true, Data: openVPNStatusDTO(status)}

	case daemonipc.ActionOpenVPNDisconnect:
		if err := vm.DisconnectOpenVPN(); err != nil {
			status, statusErr := daemonOpenVPNStatus(cfg, vm)
			if statusErr != nil {
				return daemonipc.Response{OK: false, Error: err.Error() + "; read recovery status: " + statusErr.Error()}
			}
			return daemonipc.Response{OK: false, Error: err.Error(), Data: status}
		}
		status, err := daemonOpenVPNStatus(cfg, vm)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: status}

	case daemonipc.ActionOpenVPNStatus:
		status, err := daemonOpenVPNStatus(cfg, vm)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: status}

	case daemonipc.ActionOpenVPNPrepareChallenge:
		if err := vm.PrepareOpenVPNChallenge(cmd.ChallengeID); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionOpenVPNCompleteChallenge:
		if err := vm.CompleteOpenVPNChallenge(cmd.ChallengeID, cmd.Username, cmd.Password, cmd.Secret); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: openVPNStatusDTO(vm.WaitOpenVPNState(2 * time.Second))}

	case daemonipc.ActionOpenVPNCancelChallenge:
		if err := vm.CancelOpenVPNChallenge(cmd.ChallengeID); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionListProxyGroups:
		groups, err := vm.ProxyGroups()
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: groups}

	case daemonipc.ActionSelectProxy:
		if err := vm.SelectProxy(cmd.GroupTag, cmd.OutboundTag); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true}

	case daemonipc.ActionTestProxyGroup:
		delays, err := vm.TestProxyGroup(cmd.GroupTag)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: delays}

	case daemonipc.ActionSetFollowSplitRoutes:
		vm.SetFollowSplitRoutes(cmd.FollowSplitRoutes != nil && *cmd.FollowSplitRoutes)
		return daemonipc.Response{OK: true}

	case daemonipc.ActionReloadConfig:
		updated, err := config.LoadDaemonConfig(configState.configPath, *authorizedUIDFlag, *authorizedGIDFlag, *rootOnlyFlag)
		if err != nil {
			return daemonipc.Response{OK: false, Error: "reload config: " + err.Error()}
		}
		if err := vm.Reload(updated); err != nil {
			return daemonipc.Response{OK: false, Error: "reload core: " + err.Error()}
		}
		configState.Store(updated)
		setupLogging(updated)
		cm.Configure(updated.Corplink)
		return daemonipc.Response{OK: true}

	case daemonipc.ActionConnect:
		// An explicit user connect cancels the advertised backoff, but keeps
		// Reconnecting=true while the replacement is actually being built.
		// Clearing it here would transiently report disconnected + proxy
		// endpoint still alive as "fully disconnected".
		reconnectMetrics.backoffTo.Store(0)
		lastFollowSplit, haveLast := vm.LastFollowSplitRoutes()
		followSplitRoutes := resolveConnectMode(lastFollowSplit, haveLast, cmd.FollowSplitRoutes)
		session, _ := activeConnection.Session()
		hadSession := session != nil
		resp := handleConnect(ctx, cl, cm, vm, configState, cmd.NodeID, followSplitRoutes)
		// If there was no reconnect loop to carry the state forward, a failed
		// manual connect must not leave a stale reconnecting bit behind.
		// When a session exists, its auto-reconnect loop remains authoritative
		// and must keep reporting the ongoing retry campaign.
		if !resp.OK && !hadSession {
			vm.SetReconnecting(false)
			reconnectMetrics.backoffTo.Store(0)
		}
		return resp

	case daemonipc.ActionDisconnect:
		activeConnection.Stop()
		if err := vm.Disconnect(); err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		reconnectMetrics.backoffTo.Store(0)
		return daemonipc.Response{OK: true}

	case daemonipc.ActionStatus:
		st := vm.GetStatus()
		ps := vm.ProbeStats()
		publicStatus := vm.PublicProxyStatus()
		return daemonipc.Response{OK: true, Data: daemonipc.VPNStatusDTO{
			DaemonVersion:                 Version,
			Connected:                     st.Connected,
			Reconnecting:                  st.Reconnecting,
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

			CoreRunning:          publicStatus.CoreRunning,
			TUNEnabled:           publicStatus.TUNEnabled,
			ProxyAvailable:       publicStatus.ProxyAvailable,
			PublicProxyEnabled:   publicStatus.SystemProxyEnabled,
			PublicDefault:        publicStatus.DefaultOutbound,
			PublicSelected:       publicStatus.SelectedOutbound,
			PublicSelectedType:   publicStatus.SelectedType,
			PublicChain:          publicStatus.Chain,
			SystemTUNInterface:   publicStatus.SystemTUNInterface,
			ExternalTUNs:         publicStatus.ExternalTUNs,
			CompatibleTUNs:       publicStatus.CompatibleTUNs,
			PublicRouteConflicts: publicStatus.PublicRouteConflicts,
			DNSMode:              publicStatus.DNSMode,
			DNSServers:           publicStatus.DNSServers,
			DNSProtected:         publicStatus.DNSProtected,
			DomesticDirect:       publicStatus.DomesticDirect,
			DomesticRuleSets:     publicStatus.DomesticRuleSets,

			ProbeCycles:              ps.Cycles,
			ProbeFailures:            ps.Failures,
			ProbeConsecutive:         ps.Consecutive,
			ProbeThreshold:           ps.Threshold,
			ProbeDNSFlakySkips:       ps.DNSFlakySkips,
			ProbeHostStallSkips:      ps.HostStallSkips,
			ProbeLastAt:              ps.LastCycleUnix,
			ProbeLastOutcome:         ps.LastOutcome,
			ProbeTotalCycles:         ps.TotalCycles,
			ProbeTotalFailures:       ps.TotalFailures,
			ProbeTotalDNSFlakySkips:  ps.TotalDNSFlakySkips,
			ProbeTotalHostStallSkips: ps.TotalHostStallSkips,
			ProbeTrafficVetoes:       ps.TrafficVetoes,
			ProbeTotalTrafficVetoes:  ps.TotalTrafficVetoes,
			LastTunnelOKAt:           ps.LastTunnelOKUnix,
			LastDeadReason:           ps.LastDeadReason,
			LastDeadAt:               ps.LastDeadAt,
			ReconnectTotal:           reconnectMetrics.total.Load(),
			ReconnectLastAt:          reconnectMetrics.lastUnix.Load(),
			ReconnectBackoffTo:       reconnectMetrics.backoffTo.Load(),
		}}

	case daemonipc.ActionGetStats:
		s := vm.GetStats()
		return daemonipc.Response{OK: true, Data: daemonipc.VPNStatsDTO{
			TxBytes: s.TxBytes,
			RxBytes: s.RxBytes,
		}}

	case daemonipc.ActionGetPublicIPInfo:
		probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		info, err := vm.PublicEgressInfo(probeCtx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: daemonipc.IPInfoDTO{
			IP: info.IP, City: info.City, Region: info.Region, Country: info.Country,
			Loc: info.Loc, Org: info.Org, Timezone: info.Timezone,
		}}

	case daemonipc.ActionGetCorporateIPInfo:
		probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		info, err := vm.CorporateEgressInfo(probeCtx)
		if err != nil {
			return daemonipc.Response{OK: false, Error: err.Error()}
		}
		return daemonipc.Response{OK: true, Data: daemonipc.IPInfoDTO{
			IP: info.IP, City: info.City, Region: info.Region, Country: info.Country,
			Loc: info.Loc, Org: info.Org, Timezone: info.Timezone,
		}}

	default:
		return daemonipc.Response{OK: false, Error: "unknown action: " + cmd.Action}
	}
}

func daemonOpenVPNStatus(cfg *config.Config, vm *vpnpkg.Manager) (daemonipc.OpenVPNStatusDTO, error) {
	dataDir, profilePath, err := cfg.OpenVPNProfilePath()
	if err != nil {
		return daemonipc.OpenVPNStatusDTO{}, err
	}
	status := vm.OpenVPNStatus()
	if _, err := openvpnprofile.LoadManaged(dataDir, profilePath); err == nil {
		status.Configured = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return daemonipc.OpenVPNStatusDTO{}, fmt.Errorf("load OpenVPN profile status: %w", err)
	}
	return openVPNStatusDTO(status), nil
}

func openVPNStatusDTO(status vpnpkg.OpenVPNStatus) daemonipc.OpenVPNStatusDTO {
	result := daemonipc.OpenVPNStatusDTO{
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
		RouteCount:  status.RouteCount,
		DomainCount: status.DomainCount,
	}
	if status.Challenge != nil {
		result.Challenge = &daemonipc.OpenVPNChallengeDTO{
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

// resolveConnectMode keeps the previous split/full-tunnel choice when an IPC
// client omits the field.
func resolveConnectMode(last, haveLast bool, requested *bool) bool {
	value := false
	if haveLast {
		value = last
	}
	if requested != nil {
		value = *requested
	}
	return value
}

func handleConnect(ctx context.Context, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, configState *daemonConfigState, nodeID int, followSplitRoutes bool) daemonipc.Response {
	if session, currentGen := activeConnection.Session(); session != nil {
		resp, _, adopted := session.Reconnect(func() (daemonipc.Response, connectDetails) {
			return connectVPNOnce(ctx, cl, cm, vm, configState.Load(), nodeID, followSplitRoutes)
		}, func() bool {
			return activeConnection.IsCurrent(currentGen)
		})
		if !resp.OK {
			return resp
		}
		if !adopted {
			vm.Disconnect() //nolint:errcheck
			cleanupAfterReconnectDisconnect(false)
			return daemonipc.Response{OK: false, Error: "connect superseded by disconnect"}
		}
		connCtx, connGen := activeConnection.Start(context.Background())
		activeConnection.AttachSession(connGen, session)
		startConnectionLoops(connCtx, connGen, session, cl, cm, vm, configState, nodeID, followSplitRoutes)
		return resp
	}

	resp, details := connectVPNOnce(ctx, cl, cm, vm, configState.Load(), nodeID, followSplitRoutes)
	if !resp.OK {
		return resp
	}
	connCtx, connGen := activeConnection.Start(context.Background())
	session := newSessionCoordinator(sessionRef{node: details.node, vpnIP: details.wgInfo.VpnIP.String(), pubB64: details.pubB64})
	activeConnection.AttachSession(connGen, session)
	startConnectionLoops(connCtx, connGen, session, cl, cm, vm, configState, nodeID, followSplitRoutes)
	return resp
}

type connectDetails struct {
	node             corplink.VPNNode
	wgInfo           *corplink.WGConnInfo
	pubB64           string
	serverRegistered bool
}

type resolveControlIPv4Func func(context.Context) ([]string, error)
type addControlHostRouteFunc func(ip, iface string) error

func resolvePhysicalInterface(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if configured := strings.TrimSpace(cfg.DirectOutbound.Interface); configured != "" {
		return configured
	}
	direct := outbound.NewDirect("", nil)
	if err := direct.Init(); err != nil {
		log.Printf("[corplink] resolve physical interface: %v", err)
		return ""
	}
	return direct.ResolvedIfaceName()
}

// prepareCorplinkControlPath pins every physical-DNS address before the API
// request. In particular, it must not use net.DefaultResolver after an
// external OpenVPN client has installed split-horizon DNS.
func prepareCorplinkControlPath(ctx context.Context, cl *corplink.Client, cfg *config.Config) string {
	iface := resolvePhysicalInterface(cfg)
	if iface == "" {
		return ""
	}
	if err := pinCorplinkControlRoutes(ctx, cl.ResolveServerIPv4, iface, netroute.AddScopedHostRoute); err != nil {
		// The HTTP transport is independently bound to iface, so a route pin is
		// defense in depth. Report failure but preserve the request path.
		log.Printf("[corplink] prepare control route: %v", err)
	}
	return iface
}

func pinCorplinkControlRoutes(ctx context.Context, resolve resolveControlIPv4Func, iface string, addRoute addControlHostRouteFunc) error {
	if resolve == nil || strings.TrimSpace(iface) == "" || addRoute == nil {
		return nil
	}
	addresses, err := resolve(ctx)
	if err != nil {
		return err
	}
	var routeErrors []error
	for _, address := range addresses {
		if err := addRoute(address, iface); err != nil {
			routeErrors = append(routeErrors, fmt.Errorf("pin %s to %s: %w", address, iface, err))
		}
	}
	return errors.Join(routeErrors...)
}

func connectVPNOnce(ctx context.Context, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, cfg *config.Config, nodeID int, followSplitRoutes bool) (daemonipc.Response, connectDetails) {
	// Remove stale pins first, then resolve and pin every control-server A
	// record through physical bootstrap DNS before ListNodes opens a fresh
	// connection. System DNS may be split-horizon after OpenVPN connects.
	scanAndDeleteStaleKernelHostRoutes()
	physIface := prepareCorplinkControlPath(ctx, cl, cfg)
	nodes, err := cl.ListNodes(ctx)
	if err != nil {
		return daemonipc.Response{OK: false, Error: "list nodes: " + err.Error()}, connectDetails{}
	}
	var node corplink.VPNNode
	found := false
	for _, n := range nodes {
		if n.ID == nodeID {
			node = n
			found = true
			break
		}
	}
	if !found {
		return daemonipc.Response{OK: false, Error: fmt.Sprintf("node %d not found", nodeID)}, connectDetails{}
	}

	privB64, pubB64, err := corplink.GenerateKeyPair()
	if err != nil {
		return daemonipc.Response{OK: false, Error: "keygen: " + err.Error()}, connectDetails{}
	}

	// Defense in depth: scrub stale kernel host routes before dialing the
	// node's API endpoint. If the user roamed networks while disconnected,
	// the host route from the previous network points at an unreachable
	// gateway and GetWGConfig immediately fails with
	// `connect: can't assign requested address`. startup-cleanup and
	// netroute.OnRefresh do not cover this path.
	scanAndDeleteStaleKernelHostRoutes()

	wgInfo, err := cl.GetWGConfig(ctx, node, pubB64, cm.Session().TOTPSecret)
	if err != nil {
		return daemonipc.Response{OK: false, Error: "wg config: " + err.Error()}, connectDetails{}
	}
	details := connectDetails{node: node, wgInfo: wgInfo, pubB64: pubB64, serverRegistered: true}
	log.Printf("[vpn] server wg config: node=%s endpoint=%s vpnIP=%s mtu=%d dns=%v splitRoutes=%d domains=%d",
		node.Name, wgInfo.ServerEndpoint, wgInfo.VpnIP, wgInfo.MTU, wgInfo.DNSServers, len(wgInfo.SplitRoutes), len(wgInfo.DomainSuffixes))

	serverHost, _, _ := net.SplitHostPort(wgInfo.ServerEndpoint)

	// Parse fallback DNS from upstream config for use when VPN provides no DNS.
	var fallbackDNS netip.Addr
	for _, u := range cfg.DNS.Upstream {
		host, _, _ := net.SplitHostPort(u)
		if addr, err := netip.ParseAddr(host); err == nil {
			fallbackDNS = addr
			break
		}
	}

	cc := vpnpkg.ConnectConfig{
		WG: wgdevice.Config{
			PrivateKeyB64:      privB64,
			ServerPublicKeyB64: wgInfo.ServerPublicKey,
			ServerEndpoint:     wgInfo.ServerEndpoint,
			ProtocolMode:       wgInfo.ProtocolMode,
			VpnIP:              wgInfo.VpnIP,
			DNSServers:         wgInfo.DNSServers,
			FallbackDNS:        fallbackDNS,
			MTU:                wgInfo.MTU,
		},
		SplitRoutes:       wgInfo.SplitRoutes,
		DomainSuffixes:    wgInfo.DomainSuffixes,
		PhysicalIface:     physIface,
		ServerIP:          serverHost,
		FollowSplitRoutes: followSplitRoutes,
	}

	if err := vm.Connect(node.Name, cc); err != nil {
		return daemonipc.Response{OK: false, Error: "connect: " + err.Error()}, details
	}
	proto := "UDP"
	if node.ProtocolMode == 2 {
		proto = "TCP"
	}
	dns := ""
	if len(wgInfo.DNSServers) > 0 {
		dns = wgInfo.DNSServers[0].String()
	}

	return daemonipc.Response{OK: true, Data: daemonipc.VPNStatusDTO{
		Connected:   true,
		NodeName:    node.Name,
		VpnIP:       wgInfo.VpnIP.String(),
		DNS:         dns,
		Protocol:    proto,
		ConnectedAt: time.Now().Unix(),
	}}, details
}

// sessionRef is the connection identity /vpn/report is sent with.
type sessionRef struct {
	node   corplink.VPNNode
	vpnIP  string
	pubB64 string
}

type splitRouteUpdate struct {
	routes   []string
	suffixes []string
}

// queueSplitRouteUpdate never waits for Manager lifecycle work. The channel is
// a one-element "latest value" mailbox: if the worker has not consumed the
// previous report yet, replace it rather than delaying the keepalive goroutine.
func queueSplitRouteUpdate(ch chan splitRouteUpdate, routes, suffixes []string) {
	update := splitRouteUpdate{
		routes:   append([]string(nil), routes...),
		suffixes: append([]string(nil), suffixes...),
	}
	select {
	case ch <- update:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- update:
	default:
	}
}

func runSplitRouteUpdateLoop(ctx context.Context, vm *vpnpkg.Manager, updates <-chan splitRouteUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case update := <-updates:
			// UpdateSplitRoutes itself uses lifecycleMu.TryLock, so this worker
			// cannot become a hidden lifecycle-lock waiter.
			vm.UpdateSplitRoutes(update.routes, update.suffixes)
		}
	}
}

func reconnectMode(vm *vpnpkg.Manager, fallback bool) bool {
	followSplit, ok := vm.LastFollowSplitRoutes()
	if ok {
		return followSplit
	}
	return fallback
}

func startConnectionLoops(ctx context.Context, gen uint64, session *sessionCoordinator, cl *corplink.Client, cm *corplink.Manager, vm *vpnpkg.Manager, configState *daemonConfigState, nodeID int, followSplitRoutes bool) {
	splitRouteUpdates := make(chan splitRouteUpdate, 1)
	go runSplitRouteUpdateLoop(ctx, vm, splitRouteUpdates)
	networkChanges := make(chan struct{}, 1)
	go watchPhysicalNetwork(ctx, networkChanges)

	// Keep the VPN session alive (like corplink-rs keep_alive_vpn).
	// POST /vpn/report every 30 seconds to prevent server-side session expiry.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !activeConnection.IsCurrent(gen) {
				return
			}
			if !vm.GetStatus().Connected {
				// Mid-reconnect: the tunnel is briefly down while the
				// reconnect goroutine tears it down and rebuilds it. Skip this
				// beat instead of returning.
				//
				// Returning here was a silent killer: this goroutine is only
				// ever started by handleConnect, and auto-reconnect calls
				// connectVPNOnce directly — so once it returned, nothing
				// restarted it. /vpn/report stopped forever, the server
				// expired the session, and the tunnel black-holed while the
				// WireGuard layer still looked healthy (the 25s keepalive keeps
				// handshakes fresh). A reconnect whose first attempt failed
				// made this certain: the backoff is >= 30s, so this 30s ticker
				// was guaranteed to fire while Connected was false.
				//
				// User-initiated disconnect is still handled: ActionDisconnect
				// calls activeConnection.Stop(), which both cancels ctx and
				// bumps gen, so the two checks above cover it.
				continue
			}
			ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
			settings, err := session.Report(ctx2, func(reportCtx context.Context, s sessionRef) (*corplink.VPNSettings, error) {
				return cl.ReportVPN(reportCtx, s.node, s.vpnIP, s.pubB64)
			})
			cancel()
			if err != nil {
				if ctx.Err() == nil && !errors.Is(err, errSessionUnavailable) {
					log.Printf("[keepalive] report error: %v", err)
				}
			} else if settings != nil && activeConnection.IsCurrent(gen) {
				queueSplitRouteUpdate(splitRouteUpdates, settings.SplitRoutes, settings.DomainSuffixes)
			}
		}
	}()

	// Auto-reconnect: if the tunnel goes dead (WG layer stale, or the
	// data-plane probe reports a black hole), reconnect with fresh Corplink
	// API credentials. Never gives up: failed attempts back off
	// exponentially (30s → 10min cap) instead of exhausting a fixed budget —
	// the old 10×30s schedule quit for good after five minutes of gateway
	// downtime and left a daemon that only a manual reconnect could revive.
	go func() {
		attempts := 0
		reconnecting := false
		var nextAttempt time.Time
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			networkChanged := false
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-networkChanges:
				networkChanged = true
			}
			if !activeConnection.IsCurrent(gen) {
				return
			}
			st := vm.GetStatus()
			if networkChanged {
				// A physical NIC/address/default-gateway change invalidates the
				// direct Corplink path. Do not wait for the liveness ticker or
				// carry a long outage backoff onto the newly available network.
				log.Printf("[reconnect] physical network changed; resetting reconnect backoff")
				attempts = 0
				nextAttempt = time.Time{}
				reconnectMetrics.backoffTo.Store(0)
				// Keepalive reports use the same Corplink client but run
				// outside connectVPNOnce. Flush its idle pool on every
				// physical-network event, including while the tunnel is
				// already down and waiting in backoff.
				cl.CloseIdleConnections()
				if st.Connected {
					log.Printf("[reconnect] physical network changed; replacing the tunnel now")
					vm.SetReconnecting(true)
					preserved, err := vm.DisconnectForReconnect()
					if err != nil {
						log.Printf("[reconnect] disconnect after network change: %v", err)
					}
					cleanupAfterReconnectDisconnect(preserved)
					reconnecting = true
					st = vm.GetStatus()
				}
			}
			if !st.Connected && !reconnecting {
				// The tunnel is down and we did not take it down. Historically
				// this was read as "the user disconnected" and the goroutine
				// returned — but a user disconnect goes through
				// activeConnection.Stop(), which cancels ctx and bumps gen, and
				// both are already checked above. What actually reaches here is
				// a *failed* connect that tore the tunnel down (e.g. the mixed
				// proxy could not bind 7890), and returning left that state with
				// no auto-reconnect at all: only a manual reconnect could
				// recover. Fall through and let the backoff retry it.
				log.Printf("[reconnect] tunnel down and not by us — treating as recoverable")
				reconnecting = true
				vm.SetReconnecting(true)
			}
			if !st.Connected && reconnecting {
				// Keep the externally visible state true across every failed
				// attempt and its backoff, not only on the first teardown tick.
				vm.SetReconnecting(true)
			}
			if st.Connected && !vm.IsConnectionDead() {
				attempts = 0
				reconnecting = false
				nextAttempt = time.Time{}
				vm.SetReconnecting(false)
				continue
			}
			// Tunnel is dead (or previous reconnect attempt failed)
			if st.Connected {
				log.Printf("[reconnect] dead tunnel detected, tearing down TUN")
				vm.SetReconnecting(true)
				preserved, err := vm.DisconnectForReconnect()
				if err != nil {
					log.Printf("[reconnect] disconnect for reconnect: %v", err)
				}
				cleanupAfterReconnectDisconnect(preserved)
			}
			if time.Now().Before(nextAttempt) {
				continue // still backing off after a failed attempt
			}
			reconnecting = true
			attempts++
			log.Printf("[reconnect] tunnel dead, attempt %d", attempts)
			reconnectFollowSplit := reconnectMode(vm, followSplitRoutes)
			configState.operationMu.RLock()
			resp, _, adopted := session.Reconnect(func() (daemonipc.Response, connectDetails) {
				return connectVPNOnce(ctx, cl, cm, vm, configState.Load(), nodeID, reconnectFollowSplit)
			}, func() bool {
				return ctx.Err() == nil && activeConnection.IsCurrent(gen)
			})
			configState.operationMu.RUnlock()
			if resp.OK {
				// The dial can outlive a disconnect: connectVPNOnce is not
				// ctx-aware all the way down, so the user may have hit
				// disconnect while this attempt was in flight. Adopting the
				// connection now would resurrect a tunnel the user closed —
				// and since both loops are about to exit, nothing would keep
				// its session alive either. Tear it back down instead.
				if !adopted {
					log.Printf("[reconnect] succeeded but this connection was superseded — discarding")
					vm.Disconnect()
					cleanupAfterReconnectDisconnect(false)
					return
				}
				reconnectMetrics.total.Add(1)
				reconnectMetrics.lastUnix.Store(time.Now().Unix())
				reconnectMetrics.backoffTo.Store(0)
				log.Printf("[reconnect] succeeded (attempt %d)", attempts)
				attempts = 0
				reconnecting = false
				nextAttempt = time.Time{}
				vm.SetReconnecting(false)
			} else if ctx.Err() == nil {
				backoff := reconnectBackoff(attempts)
				nextAttempt = time.Now().Add(backoff)
				reconnectMetrics.backoffTo.Store(nextAttempt.Unix())
				log.Printf("[reconnect] attempt %d failed: %s (next try in %s)", attempts, resp.Error, backoff)
			}
		}
	}()
}

const (
	reconnectBaseDelay = 30 * time.Second
	reconnectMaxDelay  = 10 * time.Minute
)

// reconnectBackoff returns the wait before reconnect attempt n+1 after the
// n-th failure: 30s, 1m, 2m, 4m, ... capped at reconnectMaxDelay.
func reconnectBackoff(failedAttempts int) time.Duration {
	d := reconnectBaseDelay
	for i := 1; i < failedAttempts; i++ {
		d *= 2
		if d >= reconnectMaxDelay {
			return reconnectMaxDelay
		}
	}
	return d
}

func firstNonSystem(upstream []string) string {
	for _, u := range upstream {
		if u != "" && u != "SYSTEM" {
			return u
		}
	}
	return ""
}

func setupLogging(cfg *config.Config) {
	logFile, err := daemonLogPath(cfg)
	if err != nil {
		log.Printf("[main] resolve log path: %v", err)
		return
	}
	if err := prepareDaemonLog(cfg, logFile); err != nil {
		log.Printf("[main] secure log path: %v", err)
		return
	}
	// Lumberjack uses ordinary path-based opens for append and rotation. They
	// are safe here because prepareDaemonLog established a real, correctly
	// owned, non-writable parent and a verified non-symlink regular leaf.
	log.SetOutput(&lumberjack.Logger{
		Filename:  logFile,
		MaxSize:   parseSizeMB(cfg.Log.MaxSize),
		MaxAge:    cfg.Log.MaxAge,
		Compress:  true,
		LocalTime: true,
	})
}

func parseSizeMB(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	mul := 1
	if strings.HasSuffix(s, "GB") {
		mul, s = 1024, strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "MB") {
		s = strings.TrimSuffix(s, "MB")
	}
	s = strings.TrimSpace(s)
	var n int
	fmt.Sscanf(s, "%d", &n)
	if n <= 0 {
		return 100
	}
	return n * mul
}
