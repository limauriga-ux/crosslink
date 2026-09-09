# CrossLink

CrossLink 是一个面向 macOS 的统一网络客户端：使用一个内嵌的 sing-box 实例接管系统 TUN、DNS 和公网代理，同时把 CorpLink 企业隧道作为同一核心中的自定义 Endpoint。

项目与原 ECorpLink 仓库、配置目录、daemon、launchd 服务和发布历史完全隔离：

- 仓库：`limauriga-ux/crosslink`
- 用户数据目录：`~/.crosslink`
- daemon staging：`~/.crosslink/bin/crosslink-daemon`
- root-owned helper：`/Library/PrivilegedHelperTools/io.github.limauriga.crosslink.daemon`
- launchd：`io.github.limauriga.crosslink.daemon`
- App Bundle ID：`io.github.limauriga.crosslink`

## 网络模型

```text
macOS applications
        |
        v
sing-box TUN + DNS + route engine
        |
        +-- corporate domain/CIDR --> CorpLink Endpoint --> customized WireGuard
        +-- public proxy rules ------> selector/urltest --> proxy node
        +-- direct rules ------------> physical interface
```

核心约束：

- 只有 sing-box 创建系统 TUN；不存在两套 TUN、两套 Fake IP 或两套系统 DNS。
- CorpLink 的 UDP/TCP WireGuard 传输继续使用本仓库内的定制 `wireguard-go`。
- CorpLink 服务端动态下发的 CIDR、域名后缀和 DNS 直接更新 Endpoint 路由快照，不重启公网代理核心。
- 企业路由快照在企业隧道故障期间保留。已知企业域名会失败关闭，不回落到 DIRECT 或公网代理。
- 代理服务器和控制面域名使用物理网卡上的小范围 bootstrap DNS，避免 TUN 回环；该路径只解析代理/控制面主机名，不处理用户访问的域名。
- 公网域名通过当前所选代理节点访问固定 IP + TLS SNI 的 Cloudflare/Google DoH；企业域名继续通过 WireGuard 内的 CorpLink DNS。公网 DoH 不依赖物理网络能否直连 `1.1.1.1:443`，用户查询也不会发送到物理网卡的 UDP/53。
- 系统 TUN 启动后立即执行禁用缓存的 DNS 查询和公网 HTTPS 预检；任一失败会关闭整个 sing-box 实例并撤销 TUN/自动路由，恢复物理直连，不允许坏 DNS 把整机留在黑洞状态。
- macOS 的 `utunN` 数字只是接口标识，不是路由优先级。系统按最长前缀匹配选路：OpenVPN 的企业 `/16`、`/24` 路由会优先于 CrossLink 的公网捕获 `/1` 等路由，因此 split-tunnel OpenVPN 可共存；只有外部 VPN 同时发布 `/0` 或 `/1` 公网路由时才构成冲突。
- `tun.name` 默认留空，由 sing-tun 选择当前最高 `utun` 序号之后的可用接口。高级设置允许固定 `utunN` 便于故障排查；已占用的序号会被拒绝，不能靠调高或调低编号改变选路。
- daemon 启动后即运行 sing-box 公网代理图；CorpLink 可稍后接入，企业重连不影响公网流量。

## Profile

GUI 的“公网代理”页面支持：

- Clash/Mihomo YAML；
- sing-box JSON；
- HTTPS 订阅 URL。

所有转换均在本机完成。远程配置只允许提供代理节点、WireGuard Endpoint 和普通路由规则；其中的 TUN、DNS、服务、控制 API 和保留的 CorpLink Endpoint 不会进入运行配置。

Clash 导入会保留 `select` / `url-test` 组、支持的域名/IP/进程/端口规则、`DIRECT` 与 `REJECT` 动作。指向旧 ECorpLink 本地 SOCKS 节点的 `Company` 规则会直接迁移为内置 `corp` Endpoint；旧本地代理节点和进程绕行规则不会进入新配置。无法等价转换的规则（例如没有对应 rule-set 的 `GEOIP`）会在导入报告中明确列出。

页面同时列出 sing-box `selector` / `urltest` 代理组，支持节点切换和并行延迟测试。选择结果写入：

```text
~/.crosslink/proxy-state.json
```

节点选择在核心重载和 daemon 重启后恢复；状态文件权限为 `0600`。无法启动的新 Profile 会自动回滚到上一份并恢复旧核心。

默认 Profile 保存路径：

```text
~/.crosslink/proxy.json
```

### 规则编排

“公网代理”页面提供独立于订阅的 Clash 风格规则编排：

```text
系统保护规则 → 前置注入 → 订阅规则 → 后置注入 → 默认出口
```

- 前置规则可覆盖订阅规则；后置规则只补充订阅未命中的流量。
- 支持域名、CIDR、进程、端口和网络类型条件；目标可选代理节点/组、`DIRECT`、`REJECT` 或 `CORP` 企业链路。
- 系统 TUN 保持企业保护优先；显式 Mixed Port 则先执行前置/Profile/后置规则，再把未命中的企业域名交给 `CORP`。因此需要强制使用公网规则的下载器可采用概览页复制的代理环境变量，而不会改变系统 TUN 的企业失败关闭语义。
- `MATCH` 不允许注入；没有本地 rule-set 的 `GEOIP` / `RULE-SET` 也不接受，避免规则静默失效。
- 面板提供最终顺序、订阅规则归属和 selector 实际节点预览。规则严格校验后原子保存；核心重载失败时自动恢复上一份。

默认规则编排文件与订阅 Profile 分离，因此更新订阅不会覆盖本地策略：

```text
~/.crosslink/rules.json
```

规则文件权限为 `0600`。

### 国内规则集直连

默认启用内置的 SagerNet `geosite-cn.srs` 与 `geoip-cn.srs`：

```text
系统保护 → 前置注入 → 订阅规则 → 后置注入
→ geosite-cn DIRECT → geoip-cn DIRECT → 私网 DIRECT → 默认出口
```

- 显式用户规则和订阅规则始终优先；例如显式把小红书指向 `节点选择` 时，不会被国内库改回直连。
- 未被 Profile 覆盖的国内域名和中国 IP 走物理网卡 `DIRECT`，避免业务流量绕 ISP 节点。
- DNS 查询仍通过所选代理访问 DoH，以保持 DNS 隐私；只有实际业务连接直连国内目标。
- 规则集随应用发布并原子写入默认的 `~/.crosslink/rulesets`，不在核心启动时联网下载。自定义 `config.json` 若不在 `.crosslink` 目录，专属数据根为配置旁的 `.crosslink/`；缓存必须位于该数据根的真实子目录内。损坏内容、过宽权限或规则文件符号链接会在启动时原子修复，越界目录链接会被拒绝。
- 设置中的 `domestic_direct` 可关闭此兜底。配置变更会先验证新核心；失败时保持旧核心和 Mixed Port 运行，并恢复上一份配置文件。

当前内置文件 SHA-256：

```text
geosite-cn.srs b3340ed1d37bffb2d8cd04e79f0203b6a93771a5378692637476551ba7355a2a
geoip-cn.srs   0acf5dad38fba9db2dade29ce5e4edc6902220944f30628ae46ed16cb0ec5edd
```

### 状态含义

- **实时路由**：当前 daemon 的 sing-box 核心正在运行，节点选择与测速操作会直接作用于运行时。
- **配置预览**：GUI 只能从 `proxy.json` 读到已导入的组和节点，尚未从 daemon 取得运行状态；它不等于公网代理已启用。页面提供“更新并重启 daemon”恢复操作。
- 概览页只有在 CrossLink 自己的 TUN 实际存在、默认出口落到代理协议，并且没有第三方 TUN 抢占 `/0` 或 `/1` 公网路由时，才显示绿色 **已启用**。Clash Verge/Mihomo 等外部 TUN 冲突会显示具体接口和地址。
- 企业路由模式以 daemon 回读值为准，不再使用 GUI 本地开关推断。概览分别探测“系统实际出口”“所选公网节点出口”和“公司 WireGuard 出口”，据实标明系统当前属于哪条链路。
- 企业规则分流只接受企业下发的私有、链路本地及 CGNAT CIDR；公网企业服务按域名后缀匹配。服务端下发的公网 CIDR 和 ICANN 公共后缀会被忽略并计数，防止共享 CDN 地址把 IPPure 等无关站点带到公司出口。企业全隧道模式不受此过滤限制。

CorpLink 节点 API 即使通过 IP 地址连接，也使用已认证企业入口域名作为 TLS SNI 与证书校验名，从而兼容只含 DNS SAN 的正常证书，同时保留完整 CA/域名校验。

Profile 文件权限为 `0600`。

## 内嵌 OpenVPN（Beta）

当前 Beta 代码线提供与公网代理共用同一 sing-box 核心的 OpenVPN Client Endpoint，不启动第二套系统 TUN。公网核心已运行时，连接或断开 OpenVPN 会短暂重建统一核心；核心未运行时，单独断开不会把它启动。

- “OpenVPN”页面导入本地 `.ovpn`，并显式选择外部 CA / PKCS#12；源路径和 PKCS#12 密码不写入托管配置。
- 只接受数据平面必需的客户端、TLS、路由、DNS 和认证选项；脚本、插件、management、凭据文件和未知指令会拒绝导入。
- 用户名、密码和 OTP 只驻留当前连接内存；认证 challenge 支持补交或取消。
- 优先级：显式本地前置规则 > 认证挑战逃生 > OpenVPN Profile 声明的静态路由/域名（含服务器推送）> 订阅 Profile 规则 > 显式本地追加规则 > 国内直连 > 公网默认出口。订阅配置里的兜底规则（如 `10.0.0.0/8 → DIRECT`）不会遮蔽 OpenVPN 显式段。`OPENVPN` 规则目标在端点断开时失败关闭。当 CorpLink 服务器推送的路由/域名与 OpenVPN Profile 显式声明的静态路由或 split-DNS 域重叠时，CorpLink 端点会让位给 OpenVPN——用户导入的 Profile 是显式策略，优先于服务器动态推送。
- `.ovpn` 只有 DNS、没有 DOMAIN / DOMAIN-ROUTE 时，该 DNS 作为 OpenVPN 连接期间的默认解析器；若有域后缀，则只处理对应企业域。公网 DoH 仍用于未匹配查询。
- OpenVPN Endpoint 使用 `system: false`，不会自行安装系统 TUN、系统路由或系统 DNS；CrossLink 仍是唯一系统捕获面。
- 外部 OpenVPN 改变接口或 split DNS 后，CorpLink 节点列表会丢弃旧 HTTP keep-alive；控制服务器通过物理接口 bootstrap DNS 解析，并在请求前固定全部公网 A 记录，避免系统 DNS 的私网答案或旧连接导致 `/api/vpn/list` 超时。
- OpenVPN 服务器使用 IP remote、但把 HTTPS 认证页放在受管 Profile 明确声明的 split-DNS 企业域时（例如 `vpn.corp.example` 属于 `corp.example`），该 URL 视为同一企业所有并允许从 GUI 打开。用户点击“在浏览器中认证”时，daemon 只从受管 Profile 推导最窄可信作用域（split-DNS 企业后缀，或 IP remote 的精确地址）并临时发布；daemon 自己不请求一次性 URL，也不做跳转预检。作用域存活期间，其域名 DNS 走公网代理 DoH，TLS/QUIC/443 连接经内部 `crosslink-public-auth` 旁路 outbound 走当前公网出口，OAuth 跳转到同后缀的兄弟身份提供商标识也被覆盖。challenge 被服务器替换或过期后，可信公网作用域只额外保留固定 10 分钟且同一代不会滑动续期，避免正在进行的 SSO 页面突然失败；GUI 明确提示旧链接已经失效并要求使用最新链接。challenge 完成、取消、不可信、报错、核心重载或断开后立即清除并推进缓存 epoch。HTTPS、域后缀边界和公共后缀拒绝仍强制执行。

托管文件位于配置专属数据根的 `openvpn/profile.json`，目录权限 `0700`、文件权限 `0600`。这是 Beta 能力；不会自动安装或替换当前生产版应用。

依赖与发布边界：当前代码线固定 `github.com/sagernet/sing-box v1.14.0`，并通过它固定 `github.com/sagernet/sing-openvpn` 提交 `103eb5fe5eb6`。OpenVPN Client Endpoint 从 sing-box 1.14.0 才开始提供，且当前 `sing` / `sing-tun` / `sing-quic` 仍是 Beta 依赖。`scripts/check_release_channel.sh` 会拒绝无预发布后缀的版本号，构建脚本和 Taskfile 均执行该门禁；在依赖迁移至稳定版前只发布 prerelease。

已知 Beta 限制：Go race detector 在 sing-box 1.14.0 的 `route.NetworkManager` 启动阶段可报告默认接口回调与 `started` 标志之间的上游数据竞态。CrossLink 的 OpenVPN profile、静态 DNS 与 IPC 包 race 回归通过，普通全量测试和 loopback OpenVPN 生命周期通过；在上游修复或依赖升级前，该代码线不提升为 stable。

本机替换测试可使用受控切换脚本；它优先使用仓库 `dist/` 中的本地 Beta DMG，也可通过 `--dmg` 指定文件。脚本固定校验摘要，在停止服务前要求确认，自动备份 App 与 `~/.crosslink`，并支持成对回滚：

```bash
./scripts/switch_local_beta.sh status
./scripts/switch_local_beta.sh install
./scripts/switch_local_beta.sh install --dmg ./dist/CrossLink-v0.3.0-beta.7-darwin-arm64.dmg
./scripts/switch_local_beta.sh rollback
```

只有本地 DMG 不存在时，脚本才通过已登录的 GitHub CLI 下载私有 Release。备份保存在 `~/.crosslink-beta-switch/`；不要在 Beta 与稳定版之间只替换 App 而不恢复对应数据。

## 安全默认值

- CorpLink TLS 证书校验默认开启。
- `insecure_skip_verify` 仅作为私有 PKI 兼容开关，默认关闭。
- 配置、会话、Profile 和主机路由状态均写入权限为 `0700` 的目录，敏感文件使用 `0600`。
- 订阅下载只接受 HTTPS，限制响应大小和重定向次数。
- IPC 使用本地 Unix Socket、显式授权 UID 和 peer credential 校验。
- root daemon 只从配置绑定的 `.crosslink` 数据根读取配置、Profile、规则与状态；符号链接、目录逃逸和数据根外路径会被拒绝。launchd 只执行 `/Library/PrivilegedHelperTools` 下 root 拥有的 helper；安装时以应用内置 SHA-256 复核 staging 副本后再原子替换。root 日志固定写入 `/var/log/crosslink.log`。
- HTTP Body 调试默认关闭；开启后仍执行敏感字段脱敏。
- 旧版 `223.5.5.5:53` / `223.6.6.6:53` 等明文公网 DNS 配置启动时自动迁移为代理 DoH；保存配置只接受 `https://` DoH URL。

CrossLink 只适用于组织明确授权使用第三方客户端的 CorpLink VPN 环境。它不实现或绕过官方客户端的终端合规、设备姿态、EDR、动态准入等功能。

## 开发环境

- macOS 12+
- Go 1.25.5+
- Node.js 20+
- npm
- Wails v3 CLI

安装前端依赖：

```bash
cd frontend
npm ci
```

安装 Wails：

```bash
go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.98
```

生成绑定并构建前端：

```bash
wails3 generate bindings -ts -i -d frontend/src/bindings ./cmd/gui
npm --prefix frontend run build
```

构建 macOS DMG：

```bash
./scripts/build_wails.sh --target darwin --arch arm64
```

产物写入 `dist/`。发布构建使用以下 sing-box 标签：

```text
with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls,badlinkname,tfogo_checklinkname0
```

## 验证

关键契约测试：

```bash
go test -tags 'with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls,badlinkname,tfogo_checklinkname0' \
  -ldflags '-checklinkname=0' \
  ./internal/config ./internal/corplink ./internal/corpendpoint \
  ./internal/core ./internal/openvpnprofile ./internal/profile ./internal/gui ./internal/netroute \
  ./cmd/crosslink-daemon
```

`internal/core` 包含真实运行烟测：启动嵌入式 sing-box mixed inbound，通过其代理访问本地 HTTP 服务，并观察流量经 `direct` outbound 完成。

## 主要目录

```text
cmd/crosslink-daemon/   privileged daemon and CorpLink session lifecycle
cmd/gui/                Wails macOS application
internal/core/          embedded sing-box lifecycle and controlled config compiler
internal/corpendpoint/  CorpLink Endpoint, split DNS, route snapshots
internal/openvpnprofile/ secure OpenVPN import, managed profile, and static DNS transport
internal/corplink/      CorpLink authentication and gateway API
internal/profile/       local Clash/sing-box profile normalization
internal/netroute/      macOS physical-interface host-route pins
internal/wgdevice/      CorpLink userspace WireGuard adapter
wireguard-go/           customized WireGuard UDP/TCP transport and netstack
frontend/               Vue user interface
```

## License

CrossLink 按根目录 `LICENSE` 中的 GPL v3-or-later 条款发布，并保留 sing-box 的下游命名/关联条件。第三方组件及原 MIT 代码声明见 `NOTICE`。

CrossLink 与 sing-box、MetaCubeX、字节跳动、BytePlus、火山引擎均无官方关联。
