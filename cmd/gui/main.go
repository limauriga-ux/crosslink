package main

import (
	"embed"
	_ "embed"
	"log"
	"time"

	"github.com/limauriga-ux/crosslink/internal/embeddeddaemon"
	"github.com/limauriga-ux/crosslink/internal/gui"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:assets
var assets embed.FS

//go:embed daemon/crosslink-daemon
var daemonFS embed.FS

//go:embed trayicon.png
var trayIcon []byte

func main() {
	windowState := gui.LoadWindowState()
	daemonPath, daemonReplaced, err := embeddeddaemon.Ensure(embeddeddaemon.Source{
		FS:     daemonFS,
		Path:   "daemon/crosslink-daemon",
		SHA256: embeddedDaemonSHA256,
	}, "")
	if err != nil {
		log.Printf("install embedded crosslink daemon: %v", err)
	}

	svc := gui.NewService(gui.Options{
		DaemonPath:     daemonPath,
		DaemonSHA256:   embeddedDaemonSHA256,
		DaemonReplaced: daemonReplaced,
		AppVersion:     Version,
	})

	app := application.New(application.Options{
		Name:        "CrossLink",
		Description: "CorpLink VPN client with split routing",
		Services: []application.Service{
			application.NewService(svc),
		},
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		Mac: application.MacOptions{
			// The WindowClosing hook below turns a close into a hide while the
			// proxy is still serving, so the app must NOT terminate with the
			// last window — the menu-bar tray takes over from there.
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:           "CrossLink",
		URL:             "/",
		Width:           windowState.Width,
		Height:          windowState.Height,
		MinWidth:        640,
		MinHeight:       360,
		DevToolsEnabled: true,
	})

	// proxyActive reports whether the unified core is serving or reconnecting.
	// During a corporate reconnect the sing-box TUN and mixed inbound remain
	// alive, so the menu-bar control must remain visible.
	proxyActive := func() bool {
		st := svc.GetVPNStatus()
		if !st.OK {
			// 查询失败时保守保留 tray：误保留只是多一个图标，
			// 误退出会丢掉一个运行中 root 代理的全部可见性。
			return true
		}
		return st.Connected || st.MixedAddr != "" ||
			st.Reconnecting || st.ReconnectBackoffTo > time.Now().Unix()
	}

	// Closing the window never stops the daemon. If the proxy is still
	// serving, turn the close into a hide so the menu-bar tray keeps the
	// background session visible; otherwise quit for real so no zombie tray
	// icon is left behind. Quitting always keeps the daemon untouched — the
	// "断开并退出" tray item is the only disconnect path, and it is explicit.
	win.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		event.Cancel()
		if proxyActive() {
			win.Hide()
		} else {
			app.Quit()
		}
	})

	tray := app.SystemTray.New()
	// Template icon: monochrome alpha glyph, macOS auto-inverts it for the
	// menu bar's light/dark state. The old color logo rendered as a blue
	// square up there.
	tray.SetTemplateIcon(trayIcon)
	tray.SetTooltip("CrossLink")

	menu := application.NewMenu()
	statusItem := menu.Add("状态：查询中…")
	statusItem.SetEnabled(false)
	menu.AddSeparator()
	menu.Add("打开主界面").OnClick(func(*application.Context) {
		win.Show().Focus()
	})
	disconnectItem := menu.Add("断开连接")
	disconnectItem.OnClick(func(*application.Context) {
		go svc.DisconnectVPN()
	})
	menu.AddSeparator()
	menu.Add("退出（保持后台代理）").OnClick(func(*application.Context) {
		app.Quit()
	})
	menu.Add("断开并退出").OnClick(func(*application.Context) {
		go func() {
			svc.DisconnectVPN()
			app.Quit()
		}()
	})
	tray.SetMenu(menu)

	// Keep the tray status line honest. Mirrors the GUI's dual criteria:
	// serving = connected || mixedAddr != ""; in-flight = reconnecting flag
	// or a backoff still in the future (reconnecting alone can lie after a
	// failed manual connect cancels the flag but not the retry campaign).
	//
	// Started only on ApplicationStarted: InvokeSync dereferences the
	// platform impl, which is nil until Run() brings the app up — a poller
	// started eagerly panics with SIGSEGV before the first window shows
	// (the 1.3.5 launch crash).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go func() {
			for {
				st := svc.GetVPNStatus()
				var label string
				serving := st.OK && (st.Connected || st.MixedAddr != "")
				switch {
				case !st.OK:
					label = "未连接（服务未运行）"
				case st.Connected:
					label = "已连接"
				case st.Reconnecting || st.ReconnectBackoffTo > time.Now().Unix():
					if st.MixedAddr != "" {
						label = "重连中 · 代理仍可用"
					} else {
						label = "重连中"
					}
				case st.MixedAddr != "":
					label = "代理服务中 · " + st.MixedAddr
				default:
					label = "未连接"
				}
				application.InvokeSync(func() {
					statusItem.SetLabel("状态：" + label)
					tray.SetTooltip("CrossLink · " + label)
					disconnectItem.SetEnabled(serving)
				})
				time.Sleep(3 * time.Second)
			}
		}()
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
