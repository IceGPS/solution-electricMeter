import atcmd
from misc import Power
from usr.common import get_logger
from usr import EventMesh
from usr.common import Abstract
from usr.common import ProtoCol
import ustruct as struct
from usr.constant import MSG_TYPE_ENUM, CMD_MODE_ENUM, COSEM, DATAType, COSEM_ACK
from ucollections import namedtuple

# import constant

TransferCommandData = namedtuple('TransferCommandData', ['mode', 'cmd', 'value'])
logger = get_logger(__name__)


class ATProtocol(ProtoCol):
    """AT协议"""
    MODE = MSG_TYPE_ENUM.AT_MODE

    def handle(self, msg=None):
        pass


class CustomATProtocol(ATProtocol):
    """自定义AT"""
    NAME = str()

    def __init__(self):
        self.meta = None
        self.meta_name = self.NAME.split("+")[1].lower()

    def handler(self, msg: TransferCommandData = None):
        """
        当有自定义AT事件时, 我们会调用search或者setting事件
        一般我们会通过
        if msg.mode == CMD_MODE_ENUM.SEARCH:
            self.search(topic, msg)
        elif msg.mode == CMD_MODE_ENUM.SETTING:
            self.setting(topic, msg)
        但是上述方法可以简化成如下
        getattr(self, CMD_MODE_ENUM.SEARCH)(topic, msg) 等同于 self.search(topic, msg)
        getattr(self, CMD_MODE_ENUM.SETTING)(topic, msg) 等同于 self.setting(topic, msg)
        继续简化
        getattr(self, msg.mode)(topic, msg)
        @param topic:
        @param msg:
        @return:
        """
        logger.info("POST CUSTOM AT MSG: ", msg)
        ret = getattr(self, msg.mode)(msg)
        logger.info("POST REPLY CUSTOM AT MSG", ret)
        return ret

    def replay(self, result):
        """
        返回的定义
        @return:
        """
        return "+{}:{}\r\n".format(self.meta_name, result)

    def read(self, msg: TransferCommandData = None):
        """
        搜索AT指令, 子类可以直接继承, 或者重写, 这里查询一般用作查询config_store里面的数据
        @param topic:
        @param msg: TransferCommandData命名空间, 有mode模式, cmd指令, value值  三个属性
        @return:
        """
        if not self.meta:
            self.meta = EventMesh.publish("persistent_config_get", self.meta_name)
        return self.replay(self.meta)

    def write(self, msg: TransferCommandData):
        """
        设置指令, 子类可以自己重写, 一般用于更改config_store里面的数据
        @param topic:
        @param msg: TransferCommandData命名空间, 有mode模式, cmd指令, value值  三个属性
        @return:
        """
        self.meta = msg.value
        EventMesh.publish("persistent_config_store", {self.meta_name: self.meta})
        return self.replay("OK")

    def active(self, msg: TransferCommandData):
        pass


class StandardATProtocol(ATProtocol):
    '''
    模组标准AT指令响应
    '''

    def handler(self, msg: TransferCommandData = None):
        cmd = msg.cmd
        logger.info("POST STANDARD AT CMD: {}".format(cmd))
        resp = bytearray(100)
        if not cmd.endswith("\r\n"):
            cmd = cmd + "\r\n"
        state = atcmd.sendSync(cmd, resp, '', 5)
        if state == 0:
            result = resp.decode('utf-8').split("\r\n\n")[0] + "\r\n" + "OK" + "\r\n"
        else:
            result = "ERROR\r\n"
        logger.info("POST REPLY STANDARD AT CMD: {}".format(cmd))
        return result


class AT_APN(CustomATProtocol):
    NAME = "AT+APN"

    def read(self, msg: TransferCommandData = None):
        """
        # 默认调用父类是继承父类行为读取, 配置文件中的信息返回
        @param msg:有三个属性
            msg.mode: 'read',这里默认是读
            msg.cmd: b"AT+APN/r/n"
            msg.value: 设置的值默认只有set里面才有
        @return: 返回self.replay()返回或者自定义反回
        """
        return super().read(msg)

    def write(self, msg: TransferCommandData):
        """
        # 默认调用父类是继承父类行为读取, 配置文件中的信息返回
        @param msg:有三个属性
            msg.mode: 'read',这里默认是读
            msg.cmd: b"AT+APN/r/n"
            msg.value: 设置的值默认只有set里面才有
        @return: 返回self.replay()返回或者自定义反回
        """
        return super().write(msg)


class AT_GPRS(CustomATProtocol):
    NAME = "AT+GPRS"

    def read(self, msg: TransferCommandData = None):
        """
        搜索AT指令, 子类可以直接继承, 或者重写, 这里查询一般用作查询config_store里面的数据
        @param topic:
        @param msg: TransferCommandData命名空间, 有mode模式, cmd指令, value值  三个属性
        @return:
        """
        if not self.meta:
            # 返回查询的结果，gprs为一个数组list
            gprs_info_list = EventMesh.publish("persistent_config_get", self.meta_name)
            self.meta ="{},{},{}".format(gprs_info_list[0], gprs_info_list[1], gprs_info_list[2])
        return self.replay(self.meta)

    def write(self, msg: TransferCommandData):
        """
        设置指令, 子类可以自己重写, 一般用于更改config_store里面的数据
        @param topic:
        @param msg: TransferCommandData命名空间, 有mode模式, cmd指令, value值  三个属性
        @return:
        """
        data = msg.value.split(",")
        if len(data) < 3:
            result = "ERROR"
            return self.replay(result)
        else:
            eval_data = [int(data[0]), data[1], int(data[2])]
        if eval_data[2] > 65535:
            logger.error("maximum gprs value is 65536")
            result = "ERROR"
        else:
            self.meta = msg.value
            EventMesh.publish("persistent_config_store", {self.meta_name: eval_data})
            result = "OK"
        return self.replay(result)


class AT_LOGIN(CustomATProtocol):
    NAME = "AT+LOGIN"


class AT_HBTT(CustomATProtocol):
    NAME = "AT+HBTT"


class AT_HBT(CustomATProtocol):
    """查询心跳帧"""
    NAME = "AT+HBT"


class AT_CCID(CustomATProtocol):
    # 查询设备查询ICCID
    NAME = "AT+CCID"


class AT_WIMEI(CustomATProtocol):
    # 查询设备IMEI
    NAME = "AT+WIMEI"


class AT_WORKMODE(CustomATProtocol):
    """设置注册模式"""
    NAME = "AT+WORKMODE"


class AT_SVRPORT(CustomATProtocol):
    NAME = "AT+SVRPORT"


class AT_MPWD(CustomATProtocol):
    NAME = "AT+MPWD"


class AT_RESET(CustomATProtocol):
    # 复位模块
    NAME = "AT+RESET"

    def active(self, msg: TransferCommandData = None):
        Power.powerRestart()


class AT_RSTTME(CustomATProtocol):
    # 设置无通信复位时间，默认参数2400表示24小时
    NAME = "AT+RSTTME"


class AT_LTO(CustomATProtocol):
    # 设置服务模式下侦听时间，默认参数1200表示12小时
    NAME = "AT+LTO"


class AT_WASION(CustomATProtocol):
    NAME = "AT+WASION"


class AT_CSQ(CustomATProtocol):
    # 查询信号强度
    NAME = "AT+CSQ"


class AT_IPR(CustomATProtocol):
    # 查询设置模块与电表通信的串口比特率
    NAME = "AT+IPR"


class AT_PARI(CustomATProtocol):
    NAME = "AT+PARI"


class AT_IP(CustomATProtocol):
    NAME = "AT+IP"


class AT_FTP(CustomATProtocol):
    """FTP远程升级"""
    NAME = "AT+FTP"


class AT_RTOL(CustomATProtocol):
    NAME = "AT+RTOL"


class AT_SVR(CustomATProtocol):
    NAME = "AT+SVR"

    def write(self, msg: TransferCommandData):
        """
        设置指令, 子类可以自己重写, 一般用于更改config_store里面的数据
        @param topic:
        @param msg: TransferCommandData命名空间, 有mode模式, cmd指令, value值  三个属性
        @return:
        """
        if not (0 <= int(msg.value) < 2):
            result = "ERROR"
        else:
            self.meta = int(msg.value)
            EventMesh.publish("persistent_config_store", {self.meta_name: self.meta})
            result = "OK"
        return self.replay(result)


class AT_PUSH(CustomATProtocol):
    NAME = "AT+PUS"


class ATCMDResolver(Abstract):
    """
    自定义AT指令集和标准AT执行
    """
    AT = b'AT'
    END = b'\r\n'

    def __init__(self):
        self.custom_at_list: [ATProtocol] = []
        self.standard_at_cmd: ATProtocol = StandardATProtocol()
        self.log = get_logger(__name__ + "." + self.__class__.__name__)
        # self.__lock = Lock()

    def check(self, data):
        return data.startswith(self.AT) or data.startswith(self.AT.lower())

    def add_cmd(self, cmd: CustomATProtocol):
        self.custom_at_list.append(cmd)
        return self

    def parse(self, data: bytes):
        _i = 0
        if len(data) < len(self.AT):
            return False, _i
        if not self.check(data):
            return False, _i
        i = data.find(self.END)
        if i == -1:
            return False, _i
        else:
            return True, i + 2

    def post_processor_after_instantiation(self):
        # 注册事件
        for cmd_handler in self.custom_at_list:
            EventMesh.subscribe(cmd_handler.NAME, cmd_handler.handle)
        EventMesh.subscribe("AT-CMD-EXECUTE", self.execute)

    def execute(self, topic=None, msg=None):
        return self.resolver(data=msg)

    def resolver(self, data):
        """
        处理标准AT与自定义AT指令，并分发处理
        """
        print("AT data {}".format(data))
        cmd = data
        if isinstance(data, bytes):
            cmd = data.decode()
        if cmd.endswith(self.END.decode()):
            cmd = cmd[:-2]
            if cmd.endswith("?"):
                mode = CMD_MODE_ENUM.READ
                cmd_split = cmd.split("?")
            elif "=" in cmd:
                mode = CMD_MODE_ENUM.WRITE
                cmd_split = cmd.split("=")
            else:
                mode = CMD_MODE_ENUM.ACTIVE
                cmd_split = [cmd.strip("\r\n"), ""]
            cmd = cmd_split[0].upper()
            val = cmd_split[1].upper()
            transfer_cmd_data = TransferCommandData(mode, cmd, val)
            for cmd_handler in self.custom_at_list:
                if cmd == cmd_handler.NAME:
                    self.log.info("CUSTOM AT CMD {}".format(data))
                    return cmd_handler.handler(transfer_cmd_data)
        self.log.info("STANDARD AT CMD {}".format(data))
        mode = CMD_MODE_ENUM.OTHER
        cmd = cmd.upper()
        transfer_cmd_data = TransferCommandData(mode, cmd, "")
        return self.standard_at_cmd.handler(transfer_cmd_data)


############################################################ 下面是 rfc 1662协议 ##################################

class FCSUtil(object):
    """
        FCSUtil 工具解析crc16的FCS
    """
    CRC_INIT = 0xffff
    POLYNOMIAL = 0x1021
    DATA_VALUE = 0xA0
    BIT32 = 0x8000

    @classmethod
    def byte_mirror(cls, c):
        c = (c & 0xF0) >> 4 | (c & 0x0F) << 4
        c = (c & 0xCC) >> 2 | (c & 0x33) << 2
        c = (c & 0xAA) >> 1 | (c & 0x55) << 1
        return c

    @classmethod
    def calc_crc(cls, data):
        _len = len(data)
        crc = cls.CRC_INIT
        for i in range(_len):

            if (i != 0) and (i != (_len - 1)) and (i != (_len - 2)) and (i != (_len - 3)):
                c = cls.byte_mirror(data[i])
                c = c << 8

                for j in range(8):

                    if (crc ^ c) & 0x8000:
                        crc = (crc << 1) ^ cls.POLYNOMIAL
                    else:
                        crc = crc << 1

                    c = c << 1
                    crc = crc % 65536
                    c = c % 65536
        crc = 0xFFFF - crc
        crc_HI = cls.byte_mirror(crc // 256)
        crc_LO = cls.byte_mirror(crc % 256)
        crc = 256 * crc_HI + crc_LO
        return crc

    @classmethod
    def check(cls, check_sum, data):
        """

        @check_sum: int
        @data: origin full data
        @return: boolean check FCS result
        """
        return check_sum == cls.calc_crc(data)


class InfoEntity(object):
    def __init__(self):
        self.__param_id = None
        self.__param_len = None
        self.__request_id = None
        self.__request_type = None
        self.__request_data = None

    def set_param_id(self, p_param_id):
        self.__param_id = p_param_id

    def set_param_len(self, p_len):
        self.__param_len = p_len

    def set_request_id(self, p_req_id):
        self.__request_id = p_req_id

    def set_request_type(self, p_req_type):
        self.__request_type = p_req_type

    def set_request_data(self, p_req_data):
        self.__request_data = p_req_data

    def param_id(self):
        return self.__param_id

    def param_len(self):
        return self.__param_len

    def request_id(self):
        return self.__request_id

    def request_type(self):
        return self.__request_type

    def request_data(self):
        return self.__request_data

    def set_data(self, d):
        self.__request_data = d

    @staticmethod
    def build(data, mode):
        info = InfoEntity()
        try:
            if mode == COSEM.SERIA_NET:
                info.set_request_data(data)
                return
            info.set_param_id(struct.unpack("<H", data[:2])[0])
            if info.param_id() in [constant.CONSEM_COMMON_RFC1662_PARAM_ID.LQI, 0x8005, 0x8007]:
                if len(data) > 2:
                    info.set_param_len(data[2])
                    info.set_request_data(struct.unpack("{}s".format(info.param_len()), data[3:])[0])
            if mode == COSEM.SET:
                info.set_param_len(data[2])
                info.set_request_id(struct.unpack("<H", data[3:5])[0])
                info.set_request_type(data[5])
                info.set_request_data(struct.unpack("{}s".format(info.param_len() - 3), data[6:])[0])
            elif mode == COSEM.GET:
                info.set_request_id(struct.unpack("<H", data[2:])[0])
        except Exception as e:
            print("e {}".format(e))
        return info

    def clear(self):
        self.__param_id = None
        self.__param_len = None
        self.__request_id = None
        self.__request_type = None
        self.__request_data = None

    def replay(self, t, d):
        self.__request_type = t
        self.__request_data = d
        ret_data = struct.pack("<HB{}s".format(len(self.__request_data)), self.__request_id, self.__request_type,
                               self.__request_data)
        self.__param_len = len(ret_data)
        return struct.pack("<HB", self.__param_id, self.__param_len) + ret_data

    def replay_get(self, t, d):
        return self.replay(t, d)

    def replay_set(self, d):
        self.__request_data = d
        self.__request_type = None
        self.__request_id = None
        ret_data = struct.pack("<HBB", self.__param_id, 0x01, self.__request_data)
        return ret_data

    def replay_event(self, d):
        self.clear()
        self.__request_data = d
        ret_data = struct.pack("B", self.__request_data)


class RFC1662Protocol(ProtoCol):
    HEADER = 0x7e
    ADDRESS = 0xFF
    CONTROL = 0x03
    END = 0x7e

    def __init__(self):
        self.__protocol = None
        self.__positions = 0
        self.__info_len = None
        self.__info_cmd = None
        self.__info_data: InfoEntity = None
        self.__fcs = None
        self.__replay_data = ""

    def protocol(self):
        return self.__protocol

    def cmd(self):
        return self.__info_cmd

    def set_fcs(self, fcs):
        self.__fcs = fcs

    def set_info_len(self, l):
        self.__info_len = l

    def set_info_data(self, info_data):
        self.__info_data = info_data

    def set_info_cmd(self, info_cmd):
        self.__info_cmd = info_cmd

    def set_protocol(self, param):
        self.__protocol = param

    def increment(self, n):
        self.__positions += n

    def position(self):
        return self.__positions

    def info(self) -> InfoEntity:
        return self.__info_data

    @classmethod
    def build(cls, data):
        rfc_proto = RFC1662Protocol()
        if data[0] == cls.HEADER and data[1] == cls.ADDRESS and data[2] == cls.CONTROL:
            # 读取protocol，从第三个字节往后读两个字节
            rfc_proto.increment(3)
            rfc_proto.set_protocol(struct.unpack_from("<H", data[rfc_proto.position():rfc_proto.position() + 2])[0])
            rfc_proto.increment(2)

            # 继续读取info区里面的长度
            info_len = struct.unpack(">H", data[rfc_proto.position():rfc_proto.position() + 2])[0]
            rfc_proto.set_info_len(info_len)
            rfc_proto.increment(2)

            # 继续读取info区里面的命令
            info_cmd = struct.unpack("B", data[rfc_proto.position():rfc_proto.position() + 1])[0]
            rfc_proto.set_info_cmd(info_cmd)
            rfc_proto.increment(1)

            # 继续读取info区里面的参数
            info_data_len = info_len - 1
            info_data = struct.unpack("{}s".format(info_data_len),
                                      data[rfc_proto.position():rfc_proto.position() + info_data_len])[0]
            rfc_proto.set_info_data(InfoEntity.build(info_data, info_cmd))
            rfc_proto.increment(info_data_len)

            # 读取fcs校验帧
            fcs = struct.unpack("<H", data[rfc_proto.position():rfc_proto.position() + 2])[0]
            rfc_proto.increment(2)
            # 校验帧检查
            if FCSUtil.check(fcs, data):
                rfc_proto.set_fcs(fcs)
            # 读取结束字节0x7e
            end = struct.unpack("B", data[rfc_proto.position():rfc_proto.position() + 1])[0]
            rfc_proto.increment(1)
            # 判断结束帧
            if end == cls.END:
                return rfc_proto

    def pack_replay_data(self, info_data):
        self.__info_len = len(info_data) + 1
        replay_data = struct.pack("<BBBH", self.HEADER, self.ADDRESS, self.CONTROL, self.protocol()) + \
                      struct.pack(">H", self.__info_len) + struct.pack("<B", self.cmd()) + info_data + \
                      struct.pack("<H", self.__fcs) + struct.pack("<B", self.END)
        self.__fcs = FCSUtil.calc_crc(replay_data)
        self.__replay_data = replay_data[:-3] + struct.pack("<HB", self.__fcs, self.END)

    def replay_get(self, t=None, d=None, success=True):
        """
        应答get指令, 判断成功失败
        @param success:  true获取成功 false 获取失败
        @param t:   对应回复的类型 采用枚举类型{@DATAType}枚举值
        @param d:
        @return:
        """
        if success:
            info_data = self.__info_data.replay_get(t, d)
            # 进行回复时转为GET
            self.__info_cmd = COSEM.GET_RESP
            # 计算长度是info_data + 1
        else:
            self.__info_cmd = COSEM.CET_ERROR_RESP
            data_info = COSEM_ACK.FAILED
            info_data = self.__info_data.replay_set(data_info)
        self.pack_replay_data(info_data)
        return self.__replay_data

    def replay_set(self, success=True):
        """
        应答set指令
        @param success: true设置成功 false 设置失败
        @return:
        """
        data_info = COSEM_ACK.SUCCESS if success else COSEM_ACK.FAILED
        info_data = self.__info_data.replay_set(data_info)
        self.__info_cmd = COSEM.SET_RESP
        self.pack_replay_data(info_data)
        return self.__replay_data

    def reply_event(self):
        """
        应答event信息
        @return:
        """
        data_info = COSEM_ACK.SUCCESS
        info_data = self.__info_data.replay_set(data_info)
        self.__info_cmd = COSEM.SERIA_NET_RESP
        self.pack_replay_data(info_data)
        return self.__replay_data

    def print(self):
        print(("{ \n" +
               "    header=0x7e\n" +
               "    address=0xff\n" +
               "    control=0x03\n" +
               "    protocol={}\n".format(hex(self.__protocol)) +
               "    info_len={}\n".format(self.__info_len) +
               "    info_cmd={}\n".format(hex(self.__info_cmd)) +
               "    info_data={\n" +
               "       InfoEntity={\n" +
               "            param_id     = {}\n".format(
                   hex(self.info().param_id()) if self.info().param_id() else None) +
               "            param_len    = {}\n".format(self.info().param_len()) +
               "            request_id   = {}\n".format(
                   hex(self.info().request_id()) if self.info().request_id() else None) +
               "            request_type = {}\n".format(self.info().request_type()) +
               "            request_data = {}\n".format(self.info().request_data()) +
               "         }\n" +
               "    }\n" +
               "    fcs={}\n".format(self.__fcs) +
               "    end=0x7e\n" +
               "}\n"))

    def print_hex(self):
        print(["%02x" % x for x in self.__replay_data])


class ReadWriteProcess(ProtoCol):
    """
        公共父类主要负责read还是write, 给子类定义了模板, 每次当子类定义的 MODE 事件触发的时候会被执行到
    """

    def handler(self, topic, msg):
        if isinstance(msg, RFC1662Protocol):
            if msg.cmd() == COSEM.GET:
                self.read(topic, msg)
            if msg.cmd() == COSEM.SET:
                self.write(topic, msg)
        else:
            if msg.get("send"):
                self.write(topic, msg)
            else:
                self.read(topic, msg)

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class APNProcess(ReadWriteProcess):
    """读写APN"""
    MODE = 0x2801

    def read(self, topic, msg: RFC1662Protocol):
        """
        模拟apn读取
        @param topic:
        @param msg: RFC1662Protocol
        @return: 无需返回
        """
        apn_example = "3gnet.mnc001.mcc460.gprs"
        replay_data = msg.replay_get(DATAType.STR, apn_example.encode())
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg: RFC1662Protocol):
        """
        获取数据
        @param topic:
        @param msg:
        @return: RFC1662Protocol
        """
        # 获取透传的数据设置并回复
        data = msg.info().request_data().decode()
        replay_data = msg.replay_set(success=True)
        EventMesh.publish("uart_write", replay_data)


class APNUserProcess(ReadWriteProcess):
    MODE = 0x2802

    def read(self, topic, msg):
        # 模拟apn user读取, 模拟读取失败
        apn_user_example = "password"
        # replay_data = msg.replay_get(DATAType.STR, apn_user_example.encode())
        replay_data = msg.replay_get(success=False)
        msg.print()
        msg.print_hex()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class APNPasswordProcess(ReadWriteProcess):
    MODE = 0x2803

    def read(self, topic, msg):
        apn_password_example = "password"
        replay_data = msg.replay_get(DATAType.STR, apn_password_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class APNSVRpProcess(ReadWriteProcess):
    MODE = 0x2804

    def read(self, topic, msg):
        # 模拟模式0客户端模式还是1服务器模式
        apn_svrp_example = 0
        replay_data = msg.replay_get(DATAType.INT8U, apn_svrp_example.to_bytes(1, 'little'))
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg: RFC1662Protocol):
        # 模拟设置失败回复
        req_data = msg.info().request_data()
        replay_data = msg.replay_set(success=False)
        # json打印输出
        msg.print()
        # 16进制打印输出
        msg.print_hex()


class IPModeProcess(ReadWriteProcess):
    MODE = 0x2834

    def read(self, topic, msg):
        # 0是IPV4 1是IPV6
        ip_mode_example = 0
        replay_data = msg.replay_get(DATAType.INT8U, ip_mode_example.to_bytes(1, 'little'))
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class ClintIPV4Process(ReadWriteProcess):
    MODE = 0x2805

    def read(self, topic, msg):
        # 主站IP
        client_ipv4_example = "192.168.52.10"
        replay_data = msg.replay_get(DATAType.STR, client_ipv4_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg: RFC1662Protocol):
        # 模拟成功回复
        replay_data = msg.replay_set(success=True)
        msg.print()
        msg.print_hex()
        EventMesh.publish("uart_write", replay_data)


class ClientIPV6Process(ReadWriteProcess):
    MODE = 0x2835

    def read(self, topic, msg):
        # 主站IpV6
        client_IPv6_example = "2001:4860:4801:66::33"
        replay_data = msg.replay_get(DATAType.STR, client_IPv6_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class ClientPORTV4Process(ReadWriteProcess):
    MODE = 0x2806

    def read(self, topic, msg):
        # 主站IpV6
        client_port_v4_example = str(80)
        replay_data = msg.replay_get(DATAType.STR, client_port_v4_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class ClientPORTV6Process(ReadWriteProcess):
    MODE = 0x2836

    def read(self, topic, msg):
        client_port_v6_example = str(8001)
        replay_data = msg.replay_get(DATAType.STR, client_port_v6_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class SVRPORTV4Process(ReadWriteProcess):
    MODE = 0x2807

    def read(self, topic, msg):
        # 读取V4端口号
        svr_port_v4_example = str(81)
        replay_data = msg.replay_get(DATAType.STR, svr_port_v4_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class SVRPORTV6Process(ReadWriteProcess):
    MODE = 0x2837

    def read(self, topic, msg):
        # 读取V6端口号
        svr_port_v6_example = str(8002)
        replay_data = msg.replay_get(DATAType.STR, svr_port_v6_example.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)

    def write(self, topic, msg):
        pass


class IPProcess(ReadWriteProcess):
    # 获取模块IP
    MODE = 0x2808

    def read(self, topic, msg):
        # 读取sim卡 ip
        pass

    def write(self, topic, msg):
        pass


class IPV6Process(ReadWriteProcess):
    # 获取模块IPV6
    MODE = 0x2838

    def read(self, topic, msg):
        # 读取sim卡 v6 IP
        pass

    def write(self, topic, msg):
        pass


class CSQProcess(ReadWriteProcess):
    # 获取CSQ
    MODE = 0x280A

    def read(self, topic, msg):
        csq = 32
        return csq


class ICCIDProcess(ReadWriteProcess):
    # 获取ICCID
    MODE = 0x280B

    def read(self, topic, msg):
        # 读取IMEI号码
        imei = EventMesh.subscribe("persistent_config_get", "IMEI")
        imei = "863141050702529"
        replay_data = msg.replay_get(DATAType.STR, imei.encode())
        msg.print()
        EventMesh.publish("uart_write", replay_data)


class ResetProcess(ReadWriteProcess):
    # 复位, 读时获取根据0x0A判断是否是复位还是获取模块表计时间
    MODE = 0x280F

    def read(self, topic, msg):
        pass


class HeartbeatProcess(ReadWriteProcess):
    # 设置心跳
    MODE = 0x282B

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class IPPUSHV4Process(ReadWriteProcess):
    # 主站IP v4-事件上报
    MODE = 0x282C

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class IPPUSHV6Process(ReadWriteProcess):
    # 主站IP v6-事件上报
    MODE = 0x283C

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class PORTV4PUSHProcess(ReadWriteProcess):
    # 主站端口-事件上报
    MODE = 0x282D

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class PORTV6PUSHProcess(ReadWriteProcess):
    # 主站端口-事件上报-IPv6
    MODE = 0x283D

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class TimeOutResetProcess(ReadWriteProcess):
    # 无通信复位时间（单位：分钟）
    MODE = 0x282E

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class ModVerProcess(ReadWriteProcess):
    # 主站端口-事件上报-IPv6
    MODE = 0x282F

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class InactivityTimeOutProcess(ReadWriteProcess):
    # GPRS通道上的静止超时时间
    MODE = 0x2830

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class IMEIProcess(ReadWriteProcess):
    # 模块IMEI号
    MODE = 0x280C

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class GPRSKeepAliveProcess(ReadWriteProcess):
    # 表计透传格式按实际编码
    MODE = 0x281B

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class ICCIProcess(ReadWriteProcess):
    # 表计透传，格式按实际编码
    MODE = 0x281E

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class CELLIDProcess(ReadWriteProcess):
    # 默认>=5MIN,默认 30min
    MODE = 0x2826

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class PUSHTimeoutProcess(ReadWriteProcess):
    # >=60MIN 默认 1440min
    MODE = 0x2827

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class NetModeProcess(ReadWriteProcess):
    # Networking mode
    MODE = 0X2850

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class FotaAddressProcess(ReadWriteProcess):
    # fota address
    MODE = 0x2853

    def read(self, topic, msg):
        pass

    def write(self, topic, msg):
        pass


class SeriaNetProtocol(ProtoCol):
    """透传指令"""
    MODE = 0x2100

    def handler(self, topic, msg):
        print("SeriaNetProtocol {} {}".format(hex(topic), msg))
        EventMesh.publish(msg.info().request_id(), msg)


class ModuleToELEMeterProtocol(ProtoCol):
    """模块to表计"""
    MODE = 0x2200

    def handler(self, topic, msg: RFC1662Protocol):
        print("ModuleToELEMeterProtocol {} {}".format(hex(topic), msg))
        if msg.info().param_id() in []:
            EventMesh.publish(msg.info().param_id(), msg)
        else:
            EventMesh.publish(msg.info().request_id(), msg)


class ELEMeterToModuleProtocol(ProtoCol):
    """表计to模块"""
    MODE = 0x2300

    def handler(self, topic, msg: RFC1662Protocol):
        print("ELEMeterToModuleProtocol {} {}".format(hex(topic), msg))
        if msg.info().param_id() in []:
            EventMesh.publish(msg.info().param_id(), msg)
        else:
            EventMesh.publish(msg.info().request_id(), msg)


class EventReporterProtocol(ProtoCol):
    """事件主动上报"""
    MODE = 0x2400

    def handler(self, topic, msg: RFC1662Protocol):
        # 这里事件一般都不需要别的操作直接给到管道即可
        print("EventReporterProtocol {} {}".format(hex(topic), msg))
        # EventMesh.publish(msg.info().request_id(), msg)
        state = EventMesh.publish("client_send", msg.info().request_data())
        if state:
            replay_data = msg.reply_event()
            return replay_data


class RFC1662ProtocolResolver(Abstract):
    HEADER = 0x7e
    ADDRESS = 0xFF
    CONTROL = 0x03

    def __init__(self):
        self.support_col_list = []
        self.support_cmd_list = []

    def post_processor_after_instantiation(self):
        for prot in self.support_col_list:
            EventMesh.subscribe(prot.MODE, prot.handler)
        for proc in self.support_cmd_list:
            EventMesh.subscribe(proc.MODE, proc.handler)
        EventMesh.subscribe("RFC1662-PROTOCOL-EXECUTE", self.execute)

    def check(self, data):
        return data[0] == self.HEADER and data[1] == self.ADDRESS and data[2] == self.CONTROL

    def execute(self, topic=None, msg=None):
        return self.resolver(data=msg)

    def add_support_protocol(self, prot):
        self.support_col_list.append(prot)
        return self

    def add_support_process(self, proc):
        self.support_cmd_list.append(proc)
        return self

    def parse(self, data):
        # HEADER/1b ADDRESS/1b CONTROL/1b RFC_PROTO/2b INFO_LEN/2b
        _i = 0
        if len(data) < 7:
            # 不满足头部协议7字节
            return False, _i
        if data[0] == self.HEADER and data[1] == self.ADDRESS and data[2] == self.CONTROL:
            # 这里直接跳过协议 占2字节
            _i += 7
            info_len = struct.unpack(">H", data[5:7])[0]
            # 包大小等于头部7字节 + 长度 + (fcs/2b + 0x7e)
            _i = _i + info_len + 3
            # 判断包数据大小小于整包的大小,包不完整
            if len(data) < _i:
                return False, 0
            else:
                return True, _i
        else:
            return False, _i

    @classmethod
    def resolver(cls, data):
        print("RFC1662 data = {}".format(data))
        rfs: RFC1662Protocol = RFC1662Protocol.build(data)
        rfs.print()
        EventMesh.publish(rfs.protocol(), rfs)
        return None
