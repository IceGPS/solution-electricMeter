import utime
from usr.mgr import SmsManager
from usr.common import Abstract
from usr.mgr import LedBlinkManager
from usr.mgr import TcpModeManager
from usr.mgr import NetStateManager
from usr.mgr import DeviceInfoManager
from usr.mgr import BtUartManager
from usr.mgr import MainUartManager
from usr.mgr import ConfigStoreManager
from usr.mgr import InstructionSchedulingManager
from usr.mgr import ClientTcpManager, ServerTcpManager
from usr.app_ota import FtpOtaManager

class App(object):
    def __init__(self):
        self.managers = []

    def append_manager(self, manager):
        if isinstance(manager, Abstract):
            manager.post_processor_after_instantiation()
            self.managers.append(manager)
        return self

    def start(self):
        for manager in self.managers:
            manager.post_processor_before_initialization()
            manager.initialization()
            manager.post_processor_after_initialization()


if __name__ == '__main__':
    print("quec test log :main.py auto run")
    from usr.protocol import ATCMDResolver, AT_APN, AT_GPRS, AT_LOGIN, AT_HBTT, AT_HBT, AT_CCID, AT_WIMEI, \
        AT_WORKMODE, AT_SVRPORT, AT_MPWD, AT_RESET, AT_RSTTME, AT_LTO, AT_WASION, AT_CSQ, AT_IPR, AT_PARI, AT_IP, \
        AT_FTP, AT_RTOL, AT_SVR, AT_PUSH
    from usr.protocol import RFC1662ProtocolResolver, ModuleToELEMeterProtocol, ELEMeterToModuleProtocol, \
        EventReporterProtocol, \
        SeriaNetProtocol, APNProcess, APNUserProcess, APNPasswordProcess, APNSVRpProcess, IPModeProcess, \
        ClintIPV4Process, ClientIPV6Process, \
        ClientPORTV4Process, ClientPORTV6Process, SVRPORTV4Process, SVRPORTV6Process, IPProcess, IPV6Process, \
        CSQProcess, ICCIDProcess, \
        ResetProcess, HeartbeatProcess, IPPUSHV4Process, IPPUSHV6Process, PORTV4PUSHProcess, PORTV6PUSHProcess, \
        TimeOutResetProcess, ModVerProcess, \
        InactivityTimeOutProcess, IMEIProcess, GPRSKeepAliveProcess, ICCIProcess, CELLIDProcess, PUSHTimeoutProcess, \
        NetModeProcess, FotaAddressProcess

    at_cmd_resolver = ATCMDResolver()
    at_cmd_resolver.add_cmd(AT_APN()) \
        .add_cmd(AT_GPRS()) \
        .add_cmd(AT_LOGIN()) \
        .add_cmd(AT_HBTT()) \
        .add_cmd(AT_HBT()) \
        .add_cmd(AT_CCID()) \
        .add_cmd(AT_WIMEI()) \
        .add_cmd(AT_WORKMODE()) \
        .add_cmd(AT_SVRPORT()) \
        .add_cmd(AT_MPWD()) \
        .add_cmd(AT_RESET()) \
        .add_cmd(AT_RSTTME()) \
        .add_cmd(AT_LTO()) \
        .add_cmd(AT_WASION()) \
        .add_cmd(AT_CSQ()) \
        .add_cmd(AT_IPR()) \
        .add_cmd(AT_PARI()) \
        .add_cmd(AT_IP()) \
        .add_cmd(AT_FTP()) \
        .add_cmd(AT_RTOL()) \
        .add_cmd(AT_SVR()) \
        .add_cmd(AT_PUSH())
    rfc1662_protocol_resolver = RFC1662ProtocolResolver()
    rfc1662_protocol_resolver.add_support_protocol(ModuleToELEMeterProtocol()) \
        .add_support_protocol(ELEMeterToModuleProtocol()) \
        .add_support_protocol(EventReporterProtocol()) \
        .add_support_protocol(SeriaNetProtocol()) \
        .add_support_process(APNProcess()) \
        .add_support_process(APNUserProcess()) \
        .add_support_process(APNPasswordProcess()) \
        .add_support_process(APNSVRpProcess()) \
        .add_support_process(IPModeProcess()) \
        .add_support_process(ClintIPV4Process()) \
        .add_support_process(ClientIPV6Process()) \
        .add_support_process(ClientPORTV4Process()) \
        .add_support_process(ClientPORTV6Process()) \
        .add_support_process(SVRPORTV4Process()) \
        .add_support_process(SVRPORTV6Process()) \
        .add_support_process(IPProcess()) \
        .add_support_process(IPV6Process()) \
        .add_support_process(CSQProcess()) \
        .add_support_process(ICCIDProcess()) \
        .add_support_process(ResetProcess()) \
        .add_support_process(HeartbeatProcess()) \
        .add_support_process(IPPUSHV4Process()) \
        .add_support_process(IPPUSHV6Process()) \
        .add_support_process(PORTV4PUSHProcess()) \
        .add_support_process(PORTV6PUSHProcess()) \
        .add_support_process(TimeOutResetProcess()) \
        .add_support_process(ModVerProcess()) \
        .add_support_process(InactivityTimeOutProcess()) \
        .add_support_process(IMEIProcess()) \
        .add_support_process(GPRSKeepAliveProcess()) \
        .add_support_process(ICCIProcess()) \
        .add_support_process(CELLIDProcess()) \
        .add_support_process(PUSHTimeoutProcess()) \
        .add_support_process(NetModeProcess()) \
        .add_support_process(FotaAddressProcess())

    bt_uart_manager = BtUartManager()
    bt_uart_manager.add_resolver(at_cmd_resolver)
    main_uart_manager = MainUartManager()
    main_uart_manager.add_resolver(at_cmd_resolver)\
        .add_resolver(rfc1662_protocol_resolver)

    app = App()
    # app 注册
    app.append_manager(DeviceInfoManager())
    app.append_manager(ConfigStoreManager())
    app.append_manager(InstructionSchedulingManager())
    app.append_manager(SmsManager())
    app.append_manager(bt_uart_manager)
    app.append_manager(main_uart_manager)
    app.append_manager(FtpOtaManager())
    app.append_manager(ClientTcpManager())
    app.append_manager(ServerTcpManager())
    app.append_manager(LedBlinkManager())
    app.append_manager(TcpModeManager())
    app.append_manager(NetStateManager())

    # 启动
    print("quec test log :main.py run end, app start")
    app.start()
