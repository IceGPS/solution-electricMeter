import net
import sim
import modem
import usys
import checkNet
from queue import Queue
from machine import UART
import ql_fs
from machine import Pin
import sms
import dataCall
import _thread
import utime
import osTimer
import usocket as socket
from misc import Power
from usr import EventMesh
from usr.common import get_logger
from usr.common import Lock
from usr.common import Abstract
from usr.common import Serial
from usr.constant import SOCKET_ERROR_ENUM, MSG_TYPE_ENUM, CMD_MODE_ENUM, COSEM, COSEM_ACK, DATAType, CommandType

logger = get_logger(__name__)


class InstructionSchedulingManager(Abstract):
    """通道指令调度分发处理"""

    def __init__(self):
        self.__lock = Lock()
        self.__queue = Queue()
        self.log = get_logger(__name__ + "." + self.__class__.__name__)

    def post_processor_after_instantiation(self):
        EventMesh.subscribe("send_message", self.put_cmd_task)
        EventMesh.subscribe("reply_message", self.reply_message)
        _thread.start_new_thread(self.wait_cmd_task, ())

    def wait_cmd_task(self):
        self.log.info("wait_cmd_task start")
        while True:
            data = self.__queue.get()
            self.log.info("wait_cmd_task recv data: {}".format(data))
            self.scheduling_cmd(data)

    def put_cmd_task(self, topic=None, msg=None):
        self.__queue.put(msg)
        EventMesh.publish("tx_led", [500, 50, 5, 0])

    def scheduling_cmd(self, data):
        with self.__lock:
            self.log.info("scheduling_cmd recv msg: {}".format(data))
            msg = data.get("msg")[0]
            # 暂时测试这样区分AT和通讯数据，后期根据协议需求调整
            if msg.upper().startswith("AT"):
                self.at_cmd(data)
            else:
                self.business_data(data)

    def at_cmd(self, cmd):
        """AT 指令"""
        EventMesh.publish("AT-CMD-EXECUTE", cmd)

    def business_data(self, args):
        """业务数据"""
        msg_type = args.get("msg_type")
        msg = args.get("msg")[0]
        self.log.info("business_data recv msg_type: {}, msg: {}".format(msg_type, msg))
        if msg_type == 1:
            # 串口主动发送的数据，直接通过Client透传到服务端
            # 这里需考虑如果模组作为服务端收到接入连接发来数据发送给串口后串口的返回数据是走client回复还是接入的连接
            # 暂时都通过client返回，后期根据需求调整
            data = {"msg_type": 3, "msg": ["Module uart send: {}".format(msg)]}
            self.reply_message(None, data)
        elif msg_type == 2 or msg_type == 3:
            # TCP read的数据透传给串口
            EventMesh.publish("uart_write", "From tcp client send : {}\r\n".format(msg))
        else:
            self.log.info("msg_type 0 is sms, pass")

    def reply_message(self, topic=None, data=None):
        """回复数据"""
        self.log.info("reply_message : {}".format(data))
        if data.get("msg_type") == CommandType.SMS_MSG:
            EventMesh.publish("S", data.get("msg"))
        elif data.get("msg_type") == CommandType.MAIN_UART_MSG:
            EventMesh.publish("uart_write", data.get("msg")[0])
        elif data.get("msg_type") == CommandType.TCP_CLI_MSG:
            EventMesh.publish("client_send", data.get("msg")[0])
        elif data.get("msg_type") == CommandType.TCP_SER_MSG:
            EventMesh.publish("server_send", data.get("msg"))
        else:
            self.log.error("received unknown command")

class TcpModeManager(Abstract):
    """TCP mode 管理"""

    def __init__(self):
        self.__tcp_mode = 0
        self.log = get_logger(__name__ + "." + self.__class__.__name__)

    def post_processor_after_initialization(self):
        EventMesh.subscribe("tcp_start", self.tcp_start)
        self.__tcp_mode = EventMesh.publish("persistent_config_get", "svr")

    def tcp_start(self, topic=None, data=None):
        # TCP 启动
        self.client_start()
        if int(self.__tcp_mode):
            self.server_start()

    def client_start(self):
        # 客户端启动
        EventMesh.publish("start_client")

    def server_start(self):
        # 服务端启动
        EventMesh.publish("start_server")

class NetStateManager(Abstract):
    """注网状态管理"""

    def __init__(self):
        self.__data_call = dataCall
        self.__net = net
        self.check_net = checkNet.CheckNetwork("QuecPython_Helios_Framework", "this latest version")
        self.timer = osTimer()
        self.check_net_timeout = 100 * 1000
        self.log = get_logger(__name__ + "." + self.__class__.__name__)

    def post_processor_after_initialization(self):
        self.wait_connect(30)
        self.__data_call.setCallback(self.net_state_cb)

    def wait_connect(self, timeout):
        """等待设备找网"""
        self.log.info("wait net -----------")
        EventMesh.publish("net_led", [600, 600, 0, 0])
        self.check_net.poweron_print_once()
        stagecode, subcode = self.check_net.wait_network_connected(timeout)
        if stagecode == 3 and subcode == 1:
            # 注网成功
            self.log.info("module net success, run tcp_start")
            EventMesh.publish("net_led", [75, 3000, 0, 1])
            EventMesh.publish('tcp_start')
        elif stagecode == 1:
            self.log.error("Device sim card is exception")
        else:
            # 注网失败
            self.log.error("module net fail, wait try again")
            self.net_fail_process()

    def net_fail_process(self):
        # 注网失败，尝试Cfun后重新找网，若Cfun失败则模组重启
        state = net.setModemFun(0)
        if state == -1:
            self.log.error("cfun net mode error, device will restart.")
            utime.sleep(5)
            Power.powerRestart()
        state = net.setModemFun(1)
        if state == -1:
            self.log.error("cfun net mode error, device will restart.")
            utime.sleep(5)
            Power.powerRestart()
        self.log.info("cfun net mode success, note the net again")
        self.wait_connect(30)

    def net_state_cb(self, args):
        """网络状态变化，会触发该回调函数"""
        nw_sta = args[1]
        if nw_sta == 1:
            EventMesh.publish("net_led", [75, 3000, 0, 1])
            self.log.info("network connected!")
        else:
            EventMesh.publish("net_led", [600, 600, 0, 0])
            self.log.info("network not connected!")

class DeviceInfoManager(Abstract):
    """设备信息管理"""

    def __init__(self):
        self.__iccid = ""
        self.__imei = ""
        self.__fw_version = ""
        self.log = get_logger(__name__ + "." + self.__class__.__name__)

    def post_processor_after_instantiation(self):
        # 注册事件
        EventMesh.subscribe("get_sim_iccid", self.get_iccid)
        EventMesh.subscribe("get_device_imei", self.get_imei)
        EventMesh.subscribe("get_fw_version", self.get_device_fw_version)
        EventMesh.subscribe("get_csq", self.get_csq)
        EventMesh.subscribe("get_ip", self.get_ip)

    def get_iccid(self, event=None, msg=None):
        print("-----------------------------------")
        """查询 ICCID"""
        if self.__iccid == "":
            msg = sim.getIccid()
            if msg != -1:
                self.__iccid = msg
            else:
                self.log.warn("get sim iccid fail, please check sim")
        return self.__iccid

    def get_imei(self, event=None, msg=None):
        """查询 IMEI"""
        if self.__imei == "":
            self.__imei = modem.getDevImei()
        return self.__imei

    def get_device_fw_version(self, event=None, msg=None):
        """查询 固件版本"""
        if self.__fw_version == "":
            self.__fw_version = modem.getDevFwVersion()
        return self.__fw_version

    def get_csq(self, event=None, msg=None):
        """查询 信号值"""
        return net.csqQueryPoll()

    def get_ip(self, event=None, msg=None):
        """查询 IP，当前获取的是IPV4，如果不是物联网卡则需要获取IPV6"""
        call_info = dataCall.getInfo(1, 0)
        if call_info == -1:
            return False
        else:
            call_state = call_info[2][0]
            if call_state:
                ip_v4_info = call_info[2][2]
                return ip_v4_info
            else:
                return False

class BtUartManager(Abstract):
    """
    串口
    """

    def __init__(self):
        self.no = UART.UART1
        self.bate = 9600
        self.data_bits = 8
        self.parity = 0
        self.uart = None
        self.stop_bits = 1
        self.flow_control = 0
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        self.resolver_list = []

    def post_processor_after_instantiation(self):
        for rsl in self.resolver_list:
            rsl.post_processor_after_instantiation()
        self.uart = Serial(self.no, self.bate, self.data_bits, self.parity, self.stop_bits, self.flow_control)
        EventMesh.subscribe("bt_uart_write", self.write)
        _thread.start_new_thread(self.serial_data_process, (self,))

    @staticmethod
    def serial_data_process(args):
        self = args
        data = b''
        while True:
            r = self.uart.read(128, -1)  # 阻塞等待
            print("bt r = {} data = {}".format(r, data))
            if not r:
                print("recv null serial data = {}".format(r))
                continue
            data = data + r
            if len(data) < 3:
                self.log.warn("recv data len lt 3 while continue")
                continue
            check_flag = False
            for resolver in self.resolver_list:
                if resolver.check(data):
                    check_flag = True
                    self.log.info("check success use {} to resolver".format(resolver))
                    break
            if not check_flag:
                self.log.error("drop rubbish data {}".format(data))
                data = b''
                continue
            while True:
                flag = False
                if not data:
                    break
                for resolver in self.resolver_list:
                    state, _i = resolver.parse(data)
                    if state:
                        if not flag:
                            flag = True
                        try:
                            ret = resolver.resolver(data[:_i])
                            # 允许有些处理器回返回值写入
                            if ret:
                                self.write(data=ret)
                        except Exception as e:
                            usys.print_exception(e)
                        data = data[_i:]
                if not flag:
                    # 如果两次都没进入证明当前数据不完整, 继续下一轮
                    print("incomplete serial data sets = {}".format(data))
                    break

    def write(self, topic=None, data=None):
        # self.log.info("write msg:{}".format(data))
        self.uart.write(data)

    def read(self, number):
        return self.uart.read(number).strip(b"\r\n")

    def uart_cb(self, data):
        """
        uart回调函数
        :param data: data是个元组包括（状态，通道，可读数据）
        :return:
        """
        raw_data = self.read(data[2])
        # self.log.info(raw_data)
        self.resolver(raw_data)

    def add_resolver(self, rsl):
        self.resolver_list.append(rsl)
        return self

class MainUartManager(Abstract):
    """
    串口
    """

    def __init__(self):
        self.no = UART.UART2
        self.bate = 9600
        self.data_bits = 8
        self.parity = 0
        self.uart = None
        self.stop_bits = 1
        self.flow_control = 0
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        self.resolver_list = []

    def post_processor_after_instantiation(self):
        # self.bate = EventMesh.publish("persistent_config_get", "ipr")
        # self.parity = EventMesh.publish("persistent_config_get", "pari")
        for rsl in self.resolver_list:
            rsl.post_processor_after_instantiation()
        self.uart = Serial(self.no, self.bate, self.data_bits, self.parity, self.stop_bits, self.flow_control)
        EventMesh.subscribe("uart_write", self.write)
        _thread.start_new_thread(self.serial_data_process, (self,))

    @staticmethod
    def serial_data_process(args):
        self = args
        data = b''
        while True:
            r = self.uart.read(128, -1)  # 阻塞等待
            print("r = {} data = {}".format(r, data))
            if not r:
                print("recv null serial data = {}".format(r))
                continue
            data = data + r
            if len(data) < 3:
                self.log.warn("recv data len lt 3 while continue")
                continue
            check_flag = False
            for resolver in self.resolver_list:
                if resolver.check(data):
                    check_flag = True
                    self.log.info("check success use {} to resolver".format(resolver))
                    break
            if not check_flag:
                self.log.error("drop rubbish data {}".format(data))
                data = b''
                continue
            while True:
                flag = False
                if not data:
                    break
                for resolver in self.resolver_list:
                    state, _i = resolver.parse(data)
                    if state:
                        if not flag:
                            flag = True
                        try:
                            ret = resolver.resolver(data[:_i])
                            # 允许有些处理器回返回值写入
                            if ret:
                                self.write(data=ret)
                        except Exception as e:
                            usys.print_exception(e)
                        data = data[_i:]
                if not flag:
                    # 如果两次都没进入证明当前数据不完整, 继续下一轮
                    print("incomplete serial data sets = {}".format(data))
                    break

    def write(self, topic=None, data=None):
        self.log.info("write msg:{}".format(data))
        self.uart.write(data)

    def read(self, number):
        return self.uart.read(number).strip(b"\r\n")

    def uart_cb(self, data):
        """
        uart回调函数
        :param data: data是个元组包括（状态，通道，可读数据）
        :return:
        """
        raw_data = self.read(data[2])
        self.log.info(raw_data)
        self.resolver(raw_data)

    def add_resolver(self, rsl):
        self.resolver_list.append(rsl)
        return self

    def resolver(self, data):
        """
        解析：
            先check匹配到对应的解析器  然后根据解析器 去解析对应的数据、
            允许业务选择自己去通过EventMesh去写入 uart管道
            也允许自动写入
        @param data:
        @return:
        """

class ConfigStoreManager(Abstract):
    """
        配置文件管理
    """

    def __init__(self):
        self.file_name = "/usr/conf_store.json"
        self.lock = Lock()
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        self.map = dict(
            # APN
            apn=["cmnet", "", ""],
            # gprs = [0, "222.247.55.215", 8077],
            # 服务端IP,PORT
            gprs=[0, "139.224.27.107", 9988],
            # 注册帧，在init_config方法里面会赋值
            login="DRLI;",
            # 心跳周期时间
            hbtt=180,
            # 心跳报文，在init_config方法里面会赋值
            hbt="DHB;",
            # sim iccid,在init_config方法里面会赋值
            ccid="",
            # imei,在init_config方法里面会赋值
            wimei="",
            # 注册模式，0表示用ICCID填充注册帧和心跳报文
            workmode=0,
            # 模组做服务端绑定的默认端口
            svrport=4059,
            # sms 短信密码，默认无
            mpwd="",
            # 无通信复位时间
            rsttme=2400,
            # 服务端模式下监听时间
            lto=1200,
            # 模块版本号，在init_config方法里面会赋值
            wasion="",
            # 串口波特率，默认9600
            ipr=9600,
            # 串口奇偶校验位
            pari=0,
            # 模块IP地址，在init_config方法里面会赋值
            ip="",
            # sms 短信白名单
            rtol=list(),
            # 模块tcp模式，默认0 客户端， 1 服务端
            svr=0
        )

    def post_processor_after_instantiation(self):
        # 同步设备信息补充配置参数
        # self.init_config()
        if ql_fs.path_exists(self.file_name):
            file_map = ql_fs.read_json(self.file_name)
            for k in self.map.keys():
                if k not in file_map:
                    file_map.update({k: self.map.get(k)})
            self.__store(msg=file_map)
            self.map = file_map
        else:
            self.init_config()
            self.__store()
        EventMesh.subscribe("persistent_config_get", self.__read)
        EventMesh.subscribe("persistent_config_store", self.__store)

    def init_config(self):
        if not self.map:
            raise ValueError("ConfigStoreManager map error")
        sim_iccid = EventMesh.publish("get_sim_iccid")
        device_imei = EventMesh.publish("get_device_imei")
        fw_version = EventMesh.publish("get_fw_version")
        ip = EventMesh.publish("get_ip")
        # workmode 注册模式为0表示用iccid填充注册帧和登录帧，别的选项需求中未提供
        if self.map.get("workmode") == 0:
            self.map["login"] = self.map.get("login") + sim_iccid
            self.map["hbt"] = self.map.get("hbt") + sim_iccid
        self.map["ccid"] = sim_iccid
        self.map["wimei"] = device_imei
        self.map["wasion"] = fw_version
        self.map["ip"] = ip if isinstance(ip, str) else "Error"

    def __read(self, event, msg):
        with self.lock:
            return self.map.get(msg)

    def __store(self, event=None, msg=None):
        if msg is None:
            msg = dict()
        with self.lock:
            self.map.update(msg)
            ql_fs.touch(self.file_name, self.map)

class LedManager(object):
    '''
    led 状态灯管理
    '''

    def __init__(self, gpio):
        self.pin = Pin(gpio, Pin.OUT, Pin.PULL_DISABLE, 0)
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        self._blink_task = None

    def on(self):
        self.pin.write(1)

    def off(self):
        self.pin.write(0)

    def flicker(self, bl, bd, cnt, mode=0):
        self.stop_blike()
        if mode:
            self._blink_task = _thread.start_new_thread(self.double_start_blink, ())
        else:
            self._blink_task = _thread.start_new_thread(self.start_blink, (bl, bd, cnt))

    def start_blink(self, bl, bd, cnt):
        cnt = True if cnt == 0 else cnt
        while cnt > 0:
            self.on()
            utime.sleep_ms(bd)
            self.off()
            utime.sleep_ms(bl)
            if isinstance(cnt, bool):
                continue
            cnt = cnt - 1
        self.off()

    def double_start_blink(self):
        while True:
            self.on()
            utime.sleep_ms(75)
            self.off()
            utime.sleep_ms(75)
            self.on()
            utime.sleep_ms(75)
            self.off()
            utime.sleep_ms(3000)

    def stop_blike(self):
        if self._blink_task is not None:
            try:
                _thread.stop_thread(self._blink_task)
            except Exception as err:
                self.log.error("Failed to stop_blike")
            self._blink_task = None

class LedBlinkManager(Abstract):
    """Led blink task"""

    def __init__(self):
        # rx led 的GPIO脚固件暂未开放，后续补充
        self.__net_led = LedManager(Pin.GPIO30)
        self.__tx_led = LedManager(Pin.GPIO46)
        self.log = get_logger(__name__ + "." + self.__class__.__name__)

    def post_processor_after_instantiation(self):
        # 注册事件
        EventMesh.subscribe("net_led", self.net_led)
        EventMesh.subscribe("net_led_stop", self.net_led_stop)
        EventMesh.subscribe("tx_led", self.tx_led)
        EventMesh.subscribe("tx_led_stop", self.tx_led_stop)

    def net_led(self, topic=None, data=None):
        # 网络状态指示灯
        bl, bd, cnt, mode = data
        self.__net_led.flicker(bl, bd, cnt, mode)

    def net_led_stop(self, topic=None, data=None):
        self.__net_led.stop_blike()

    def tx_led(self, topic=None, data=None):
        # 数据通信tx状态指示灯
        bl, bd, cnt, mode = data
        self.__tx_led.flicker(bl, bd, cnt, mode)

    def tx_led_stop(self, topic=None, data=None):
        self.__tx_led.stop_blike()

class SmsManager(Abstract):
    '''
    短信服务
    '''

    def __init__(self, *args, **kwargs):
        self.__code_mode = "UCS2"
        self.__sms_pwd = None
        self.__rtol = None
        self.sms_super_pwd = 546289
        self.log = get_logger(__name__ + "." + self.__class__.__name__)

    def post_processor_after_instantiation(self):
        # 注册事件
        sms.setCallback(self.sms_cb)
        self.__sms_pwd = EventMesh.publish("persistent_config_get", "mpwd")
        self.__rtol = EventMesh.publish("persistent_config_get", "rtol")
        EventMesh.subscribe("set_sms_addr", self.set_sms_addr)
        EventMesh.subscribe("sms_send", self.sms_send)
        EventMesh.subscribe("sms_delete", self.sms_delete)

    def sms_send(self, topic=None, message=None):
        '''
        发送短信
        '''
        msg, phoneNumber = message
        self.log.info("sms sent message: {}, {}".format(msg, phoneNumber))
        state = sms.sendTextMsg(phoneNumber, msg, self.__code_mode)
        self.log.info("sms sent message state: " + str(state))

    def sms_delete(self, topic=None, index=0):
        '''
        删除短信
        '''
        state = sms.deleteMsg(index)
        self.log.info("sms delete message state: " + str(state))

    def check_sms_rtol(self, phone):
        if self.__rtol:
            if phone in self.__rtol:
                return True
            return False
        else:
            return True

    def read_sms(self, index):
        '''读取短信'''
        msg_tuple = sms.searchTextMsg(index)
        if msg_tuple != -1:
            phone_number = msg_tuple[0]
            # 白名单判断
            if not self.check_sms_rtol(phone_number):
                self.log.info("check_sms_rtol return False")
                return False
            try:
                sms_pwd, sms_msg = msg_tuple[1].split("#")
            except ValueError:
                self.log.error("sms read ValueError")
                return
            if self.__sms_pwd == "" and sms_pwd != "":
                if sms_pwd != self.sms_super_pwd:
                    self.log.info("sms pwd error")
                    return False
            if self.__sms_pwd != "" and sms_pwd != "":
                if sms_pwd != self.__sms_pwd or sms_pwd != self.sms_super_pwd:
                    self.log.info("sms pwd error")
                    return False
            self.log.info("sms read message: {}, phone:{}".format(sms_msg, phone_number))
            self.sms_delete(index)
            result = EventMesh.publish("AT-CMD-EXECUTE", sms_msg.encode())
            self.sms_send(message=(result, phone_number))
            return msg_tuple
        self.log.info("sms read message error: " + str(msg_tuple))

    def get_sms_addr(self, topic=None, message=None):
        '''
        获取短信中心号码
        '''
        addr = sms.getCenterAddr()
        if addr != -1:
            return addr
        self.log.info("sms get addr error: " + str(addr))

    def set_sms_addr(self, topic=None, addr=None):
        """
        设置短信中心号码
        """
        state = sms.setCenterAddr(addr)
        if state == -1:
            self.log.info("sms set addr error: %s" % state)

    def sms_cb(self, args):
        '''
        短信监听回调
        args[1]:sms index
        args[2]:sms storage
        '''
        self.log.info("sms cb message args : " + str(args))
        self.read_sms(args[1])

class WouldBlockError(Exception):
    pass

class ClientTcpManager(Abstract):
    '''
    客户端TCP 初始化，事件处理
    '''

    def __init__(self):
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        self._host = None
        self._port = None
        self._sockaddr = None
        self._client_tcp = None
        self._task_id = None
        self._reconnect_delay = 30
        self._ping_time = 180
        self._reconnect_count = 0
        self._ping_message = None
        self._login_message = None
        self._last_time = None
        self._lock = Lock()
        self._client_ping_timer = osTimer()

    def post_processor_after_instantiation(self):
        # 事件注册
        EventMesh.subscribe("client_send", self.send_data)
        EventMesh.subscribe("start_client", self.start_client)
        EventMesh.subscribe("client_disconnect", self.disconnect)
        # 从配置文件中读取IP PORT
        gprs_list = EventMesh.publish("persistent_config_get", "gprs")
        self._host, self._port = gprs_list[1], gprs_list[2]
        # 从配置文件中读取心跳报文，注册帧，心跳时间
        self._ping_message = EventMesh.publish("persistent_config_get", "hbt")
        self._login_message = EventMesh.publish("persistent_config_get", "login")
        self._ping_time = EventMesh.publish("persistent_config_get", "hbtt")

    def connect(self):
        """socket 客户端连接"""
        self._client_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # IP 解析，返回tuple，包含IP， port
        sockaddr = socket.getaddrinfo(self._host, self._port)
        if not sockaddr:
            return False
        self._sockaddr = sockaddr[0][-1]
        if not self._client_tcp:
            return False
        # 发起连接请求
        print((self._host, self._port))
        try:
            self._client_tcp.connect((self._host, self._port))
        except:
            for i in range(0, 5):
                self.log.error("socket connect fail! please check host or port!")
                utime.sleep(1)
            return False
        self._client_tcp.settimeout(10)
        self._client_tcp.setblocking(True)
        return True

    def reconnect(self):
        """异常断开 重新连接"""
        with self._lock:
            self.log.info("Reconnecting complete")
            self.disconnect()
            if self._task_id:
                try:
                    _thread.stop_thread(self._task_id)
                except Exception as err:
                    self.log.error("Failed to reconnect delete task")
                finally:
                    self._task_id = None
            state = self.start_client()
            if state:
                return
            else:
                if self._reconnect_count >= 10:
                    Power.powerRestart()
                else:
                    self._reconnect_count += 1
                    utime.sleep(self._reconnect_delay)
                    self.reconnect()

    def send_ping(self, args):
        # 周期心跳
        self.log.info("client send ping")
        self.send_data(None, self._ping_message)

    def send_register(self):
        # 发送注册帧
        self.log.info("client send register")
        self.send_data(None, self._login_message)

    def start_client(self, topic=None, data=None):
        """启动客户端"""
        state = self.connect()
        if not state:
            self.log.info("TCP Client connect fail")
            return False
        self.log.info("TCP Client connect success")
        self._task_id = _thread.start_new_thread(self.loop_recv, ())
        self.send_register()  # 设备发送注册帧
        # 开启心跳任务
        self._client_ping_timer.start(self._ping_time * 1000, 1, self.send_ping)
        return True

    def disconnect(self):
        """Close the connection to the server."""
        if not self._client_tcp:
            return False
        try:
            self._client_tcp.close()
            self._client_tcp = None
        except Exception as err:
            self.log.error("TCP Client disconnect error")

    def is_connected(self):
        # state = self._client_tcp.getsocketsta()
        # return True if state == 4 else False
        return True

    def send_data(self, topic=None, data=None):
        """发送数据到服务端"""
        if not self.is_connected():
            self.log.error("TCP Client is_connected False")
        try:
            self._client_ping_timer.stop()  # 有数据发送前停止ping定时器
            self.log.info("TCP Client send data")
            if not isinstance(data, bytes):
                data = data.encode("utf-8")
            return self._client_tcp.send(data)
        except AttributeError as err:
            self.log.error("send data error:{}".format(str(err)))
        except Exception as err:
            self.log.error("TCP Client send data error is :{}".format(str(err)))
            self.reconnect()
            return False
        finally:
            self._client_ping_timer.start(self._ping_time * 1000, 1, self.send_ping)

    def recv_data(self, bufsize=1024):
        """socket数据接收"""
        try:
            data = self._client_tcp.recv(bufsize).decode('utf-8')
            if len(data) == 0:
                self.log.error("Module TCP Client recv msg len is 0")
                return SOCKET_ERROR_ENUM.ERR_NOMEM
            self.log.info("Module TCP Client recv msg : {}".format(data))
            EventMesh.publish("send_message", {"msg_type": 3, "msg": [data]})
            return SOCKET_ERROR_ENUM.ERR_SUCCESS
        except Exception as err:
            self.log.error("TCP Client recv data error is :{}".format(str(err)))
            return SOCKET_ERROR_ENUM.ERR_NOMEM

    def loop_recv(self):
        """循环 socket数据接收"""
        while True:
            self.log.info("tcp client loop_recv start")
            state = self.recv_data()
            if state == SOCKET_ERROR_ENUM.ERR_NOMEM:
                self.log.error("Module TCP Client error, server close ")
                self.reconnect()
                break

class ServerTcpManager(Abstract):
    """docstring for ServerClass"""

    def __init__(self):
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        self._host = None
        self._port = 4059
        self._listen_num = 5
        self._server_tcp = None
        # 用来存放套接字对象的列表
        self._inputlist = list()
        self._outputlist = list()
        self.connlist = list()
        # 存放客户端发送过来的数据
        self.msg_dict = dict()

    def post_processor_after_instantiation(self):
        """注册事件"""
        EventMesh.subscribe("server_send", self.send_data)
        EventMesh.subscribe("c", self.start_server)
        # EventMesh.subscribe("server_disconnect", self.disconnect)
        # 获取配置文件里的服务端端口
        self._port = EventMesh.publish("persistent_config_get", "svrport")

    def connect(self):
        """socket bind"""
        self.log.info("dataCall info : {}".format(dataCall.getInfo(1, 2)))
        # 这里需要注意，如果用的是物联网sim卡，则选择IPV4即可支持服务端，若不是则需要以IPV6的地址进行bind
        # 注意调整代码，参照下面示例，当前测试所用的是IPV6
        # 物联网卡：self._server_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP_SER)
        # IPV6: self._server_tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP_SER)
        self._server_tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP_SER)
        self._server_tcp.setblocking(False)
        try:
            self._server_tcp.bind(("", self._port))
        except Exception as err:
            self.log.error("Server bind error: {}".format(err))
            return False
        # 监听
        self._server_tcp.listen(self._listen_num)
        self._inputlist.append(self._server_tcp)
        self.log.info("Server is Running")
        return True

    def loop_listen(self):
        while True:
            try:
                if self.connlist:
                    # 循环套接字对象列表 进行收发数据
                    for conn in self.connlist:
                        self.recv_data(conn)
                conn, addr, port = self._server_tcp.accept()
                conn.setblocking(False)
                self.log.info("Module TCP Server, from client addr {} 已连接".format(addr))
                self.connlist.append(conn)
            # 这里目前异常是全部捕捉，要区分出非阻塞下抛出的异常且pass
            except Exception as err:
                utime.sleep(1)

    def recv_data(self, conn):
        """接收数据"""
        try:
            msg = conn.recv(1024).decode("utf-8")
            if not msg or msg in ["quit"]:
                self.log.debug("断开连接")
                # 将套接字对象从列表移除
                self.connlist.remove(conn)
            else:
                self.log.info("Module TCP Server recv msg : {}".format(msg))
                self.send_data(None, {"msg": [msg, conn]})
                msg = "From tcp server send: {}\r\n".format(msg)
                EventMesh.publish("uart_write", msg)
                # EventMesh.publish("send_message", {"msg_type": 2, "msg": [msg, conn]})
                return msg
        except OSError as err:
            # self.log.debug("recv_data OSError is {}".format(str(err)))
            pass
        except Exception as err:
            self.log.error("recv_data Exception is {}".format(str(err)))
            self.connlist.remove(conn)

    def send_data(self, topic=None, data=None):
        """发送数据"""
        msg, conn = data.get("msg")
        if msg:
            try:
                msg = "Module TCP Server send {}".format(msg)
                conn.send(msg.encode("utf-8"))
            except Exception as err:
                self.log.error("send_data Exception is {}".format(str(err)))
                self.connlist.remove(conn)

    def start_server(self, topic=None, data=None):
        # 启动服务端
        state = self.connect()
        if not state:
            self.log.info("TCP Server connect fail")
            return False
        self.log.info("TCP Server connect success")
        self._task_id = _thread.start_new_thread(self.loop_listen, ())
        return True
