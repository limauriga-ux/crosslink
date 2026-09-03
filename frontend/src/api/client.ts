import type {
  AppState,
  CommandResult,
  ConfigDocument,
  ConfigResponse,
  DaemonStatus,
  IPInfoResult,
  LaunchServiceRequest,
  LoginMethodsResult,
  QRCodeResult,
  OpenVPNImportRequest,
  OpenVPNProfileResult,
  OpenVPNStatusResult,
  ProxyDelayResult,
  ProxyGroupsResult,
	ProxyProfileResult,
  RulePlanResult,
  ServiceStatus,
  TestReport,
  ValidationResult,
  VPNNodesResult,
  VPNStatsResult,
  VPNStatusResult,
  WindowState
} from '../types'
import * as Service from '../bindings/github.com/limauriga-ux/crosslink/internal/gui/service'

type Backend = Record<string, (...args: never[]) => Promise<unknown>>

async function call<T>(name: string, ...args: unknown[]): Promise<T> {
  const fn = (Service as unknown as Backend)[name]
  if (!fn) {
    throw new Error(`后端方法不存在：${name}`)
  }
  try {
    return (await fn(...(args as never[]))) as T
  } catch (error) {
    throw new Error(`后端调用失败：${name}: ${errorMessage(error)}`)
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
  }
  if (typeof error === 'string') {
    return error
  }
  try {
    return JSON.stringify(error)
  } catch {
    return String(error)
  }
}

export const api = {
  getAppState(): Promise<AppState> {
    return call('GetAppState')
  },
  loadConfig(path = ''): Promise<ConfigResponse> {
    return call('LoadConfig', path)
  },
  saveConfig(path: string, config: ConfigDocument): Promise<ValidationResult> {
    return call('SaveConfig', path, config)
  },
  validateConfig(config: ConfigDocument): Promise<ValidationResult> {
    return call('ValidateConfig', config)
  },
  reloadConfig(): Promise<CommandResult> {
    return call('ReloadConfig')
  },
	getProxyProfile(): Promise<ProxyProfileResult> {
		return call('GetProxyProfile')
	},
	saveProxyProfile(content: string): Promise<ProxyProfileResult> {
		return call('SaveProxyProfile', content)
	},
	importProxyProfileURL(url: string): Promise<ProxyProfileResult> {
		return call('ImportProxyProfileURL', url)
	},
	getRulePlan(): Promise<RulePlanResult> {
		return call('GetRulePlan')
	},
	saveRulePlan(prepend: string[], append: string[]): Promise<RulePlanResult> {
		return call('SaveRulePlan', prepend, append)
	},
  getProxyGroups(): Promise<ProxyGroupsResult> {
    return call('GetProxyGroups')
  },
  selectProxy(groupTag: string, outboundTag: string): Promise<CommandResult> {
    return call('SelectProxy', groupTag, outboundTag)
  },
  testProxyGroup(groupTag: string): Promise<ProxyDelayResult> {
    return call('TestProxyGroup', groupTag)
  },
  startDaemon(path = ''): Promise<CommandResult> {
    return call('StartDaemon', path)
  },
  stopDaemon(): Promise<CommandResult> {
    return call('StopDaemon')
  },
  restartDaemon(path = ''): Promise<CommandResult> {
    return call('RestartDaemon', path)
  },
  getDaemonStatus(): Promise<DaemonStatus> {
    return call('GetDaemonStatus')
  },
  runConnectivityTests(): Promise<TestReport> {
    return call('RunConnectivityTests', {})
  },
  getLaunchServiceStatus(): Promise<ServiceStatus> {
    return call('GetLaunchServiceStatus')
  },
  installLaunchService(req: LaunchServiceRequest): Promise<CommandResult> {
    return call('InstallLaunchService', req)
  },
  startLaunchService(req: LaunchServiceRequest): Promise<CommandResult> {
    return call('StartLaunchService', req)
  },
  uninstallLaunchService(): Promise<CommandResult> {
    return call('UninstallLaunchService')
  },
  getWindowState(): Promise<WindowState> {
    return call('GetWindowState')
  },
  saveWindowState(state: WindowState): Promise<CommandResult> {
    return call('SaveWindowState', state)
  },
  getVersion(): Promise<string> {
    return call('GetVersion')
  },
  getOpenVPNProfile(): Promise<OpenVPNProfileResult> {
    return call('GetOpenVPNProfile')
  },
  importOpenVPNProfile(request: OpenVPNImportRequest): Promise<OpenVPNProfileResult> {
    return call('ImportOpenVPNProfile', request)
  },
  removeOpenVPNProfile(): Promise<OpenVPNProfileResult> {
    return call('RemoveOpenVPNProfile')
  },
  connectOpenVPN(username: string, password: string): Promise<OpenVPNStatusResult> {
    return call('ConnectOpenVPN', username, password)
  },
  disconnectOpenVPN(): Promise<OpenVPNStatusResult> {
    return call('DisconnectOpenVPN')
  },
  getOpenVPNStatus(): Promise<OpenVPNStatusResult> {
    return call('GetOpenVPNStatus')
  },
  prepareOpenVPNChallenge(challengeID: string): Promise<CommandResult> {
    return call('PrepareOpenVPNChallenge', challengeID)
  },
  completeOpenVPNChallenge(challengeID: string, username: string, password: string, secret: string): Promise<OpenVPNStatusResult> {
    return call('CompleteOpenVPNChallenge', challengeID, username, password, secret)
  },
  cancelOpenVPNChallenge(challengeID: string): Promise<CommandResult> {
    return call('CancelOpenVPNChallenge', challengeID)
  },

  // Corplink auth & VPN methods
  isAuthenticated(): Promise<boolean> {
    return call('IsAuthenticated')
  },
  discoverCompany(company: string): Promise<CommandResult> {
    return call('DiscoverCompany', company)
  },
  getLoginMethods(): Promise<LoginMethodsResult> {
    return call('GetLoginMethods')
  },
  sendVerifyCode(codeType: string, account: string): Promise<CommandResult> {
    return call('SendVerifyCode', codeType, account)
  },
  verifyCode(codeType: string, account: string, code: string): Promise<CommandResult> {
    return call('VerifyCode', codeType, account, code)
  },
  loginWithPassword(account: string, password: string): Promise<CommandResult> {
    return call('LoginWithPassword', account, password)
  },
  getQRCode(): Promise<QRCodeResult> {
    return call('GetQRCode')
  },
  pollQRStatus(token: string): Promise<CommandResult> {
    return call('PollQRStatus', token)
  },
  logout(): Promise<CommandResult> {
    return call('Logout')
  },
  listVPNNodes(): Promise<VPNNodesResult> {
    return call('ListVPNNodes')
  },
  pingNodes(): Promise<VPNNodesResult> {
    return call('PingNodes')
  },
  pingSingleNode(nodeID: number): Promise<VPNNodesResult> {
    return call('PingSingleNode', nodeID)
  },
  connectVPN(nodeID: number, followSplitRoutes: boolean): Promise<CommandResult> {
    return call('ConnectVPN', nodeID, followSplitRoutes)
  },
  setFollowSplitRoutes(v: boolean): Promise<CommandResult> {
    return call('SetFollowSplitRoutes', v)
  },
  disconnectVPN(): Promise<CommandResult> {
    return call('DisconnectVPN')
  },
  getVPNStatus(): Promise<VPNStatusResult> {
    return call('GetVPNStatus')
  },
  getVPNStats(): Promise<VPNStatsResult> {
    return call('GetVPNStats')
  },
  getIPInfo(proxyAddr: string): Promise<IPInfoResult> {
    return call('GetIPInfo', proxyAddr)
  },
  getPublicIPInfo(): Promise<IPInfoResult> {
    return call('GetPublicIPInfo')
  },
  getCorporateIPInfo(): Promise<IPInfoResult> {
    return call('GetCorporateIPInfo')
  },
  cleanupRoutes(): Promise<CommandResult> {
    return call('CleanupRoutes')
  }
}
