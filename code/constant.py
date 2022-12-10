class MSG_TYPE_ENUM(object):
    # at 消息
    AT_MODE = 0
    # RFC1662协议
    RFC1662 = 1
    # SMS 消息
    SMS = 2
    # 客户端消息
    TCP_CLI = 3
    # 服务端消息
    TCP_SER = 4


class CMD_MODE_ENUM(object):
    # 查询模式
    READ = "read"
    # 设置模式
    WRITE = "write"
    # 其他
    OTHER = "other"
    # active
    ACTIVE = "active"


class COSEM(object):
    GET = 0xC0
    GET_RESP = 0xC4
    CET_ERROR_RESP = 0xC8
    SET = 0xC1
    SET_RESP = 0xC5
    EVENT = 0xC2
    EVENT_RESP = 0xC6
    ACTION = 0xC3
    ACTION_RESP = 0xC7
    SERIA_NET = 0xBF
    SERIA_NET_RESP = 0xC6


class COSEM_ACK(object):
    """用于应答"""
    SUCCESS = 0x00
    FAILED = 0x0C


class DATAType(object):
    CHAR = 0x0A
    INT8U = 0x11
    INT16U = 0x12
    STR = 0x09

class CommandType(object):
    """
    外部数据来源
    0 sms 短信
    1 uart 串口，暂只支持主串口 MAIN
    2 TCP 服务端
    3 TCP 客户端
    """
    SMS_MSG = 0
    MAIN_UART_MSG = 1
    TCP_SER_MSG = 2
    TCP_CLI_MSG = 3

class SOCKET_ERROR_ENUM(object):
    ERR_AGAIN = -1
    ERR_SUCCESS = 0
    ERR_NOMEM = 1
    ERR_PROTOCOL = 2
    ERR_INVAL = 3
    ERR_NO_CONN = 4
    ERR_CONN_REFUSED = 5
    ERR_NOT_FOUND = 6
    ERR_CONN_LOST = 7
    ERR_PAYLOAD_SIZE = 9
    ERR_NOT_SUPPORTED = 10
    ERR_UNKNOWN = 13
    ERR_ERRNO = 14


class CONSEM_COMMON_RFC1662_PARAM_ID:
    LQI = 0x8003
    MODULE_STATE = 0x8002
    DEVICE_NAME = 0x8007

# 预留是socket的  具体作用pawn填充
EAGAIN = 11
FAIL = 0X01
SUC = 0X00

HANDLER = "handler"
