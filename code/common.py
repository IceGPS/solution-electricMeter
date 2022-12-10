import _thread
import utime
import usys
from machine import UART
from machine import Timer
from queue import Queue
from usr import EventMesh

DEBUG = 0
INFO = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
DESC = {
    DEBUG: "DEBUG",
    INFO: "INFO",
    WARNING: "WARNING",
    ERROR: "ERROR",
    CRITICAL: "CRITICAL",
}


def log(obj, level, *message, local_only=False, return_only=False, timeout=None):
    if level < obj._level:
        return
    name = obj.name
    level = DESC[level]
    if hasattr(utime, "strftime"):
        msg = "[{}]".format(utime.strftime("%Y-%m-%d %H:%M:%S")) + "[{}]".format(name) + "[{}]".format(level) + "".join(message)
    else:
        t = utime.localtime()
        a = [str(i) for i in message]
        msg = "[{}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}]".format(*t) + "[{}]".format(name) + "[{}]".format(level) + "".join(a)
    print(msg)
    EventMesh.publish("bt_uart_write", msg + "\r\n")
    if return_only:
        return


class Logger:
    def __init__(self, name):
        self.name = name
        self._level = DEBUG

    def set_level(self, level):
        if level > CRITICAL or level < DEBUG:
            raise Exception("日志级别错误")
        self._level = level

    def critical(self, *message, local_only=True):
        log(self, CRITICAL, *message, local_only=local_only, timeout=None)

    def error(self, *message, exc=None, local_only=True):
        log(self, ERROR, *message, local_only=local_only, timeout=None)
        if exc is not None and isinstance(exc, Exception):
            usys.print_exception(exc)

    def warn(self, *message, local_only=True):
        log(self, WARNING, *message, local_only=local_only, timeout=None)

    def info(self, *message, local_only=True):
        log(self, INFO, *message, local_only=local_only, timeout=20)

    def debug(self, *message, local_only=True):
        log(self, DEBUG, *message, local_only=local_only, timeout=5)

    def asyncLog(self, level, *message, timeout=True):
        pass


def get_logger(name):
    return Logger(name)


class Lock(object):

    def __init__(self):
        self.lock = _thread.allocate_lock()

    def __enter__(self, *args, **kwargs):
        self.lock.acquire()

    def __exit__(self, *args, **kwargs):
        self.lock.release()


class Abstract(object):
    def post_processor_after_instantiation(self, *args, **kwargs):
        """实例化后调用"""
        pass

    def post_processor_before_initialization(self, *args, **kwargs):
        """初始化之前调用"""
        pass

    def initialization(self, *args, **kwargs):
        """初始化load"""
        pass

    def post_processor_after_initialization(self, *args, **kwargs):
        """初始化之后调用"""
        pass


class ProtoCol(object):
    """
    串口协议解析
    """

    def handler(self, *args, **kwargs):
        """协议解析"""

    def resolve(self, *args, **kwargs):
        """协议解析"""


class Serial(object):
    def __init__(self,
                 uart,
                 buadrate=115200,
                 databits=8,
                 parity=0,
                 stopbits=1,
                 flowctl=0):

        self._uart = UART(uart, buadrate, databits, parity, stopbits, flowctl)
        self._queue = Queue(maxsize=1)
        self._timer = Timer(Timer.Timer1)

        self._uart.set_callback(self._uart_cb)

    def _uart_cb(self, args):
        if self._queue.size() == 0:
            self._queue.put(None)

    def _timer_cb(self, args):
        if self._queue.size() == 0:
            self._queue.put(None)

    def write(self, data):
        self._uart.write(data)

    def read(self, nbytes, timeout=0):
        if nbytes == 0:
            return ''

        if self._uart.any() == 0 and timeout != 0:
            timer_started = False
            if timeout > 0:  # < 0 for wait forever
                self._timer.start(period=timeout, mode=Timer.ONE_SHOT, callback=self._timer_cb)
                timer_started = True
            self._queue.get()
            if timer_started:
                self._timer.stop()
        r_data = self._uart.read(min(nbytes, self._uart.any()))
        if self._queue.size():
            self._queue.get()

        return r_data


if __name__ == '__main__':
    pass
