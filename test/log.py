from objict import objict
from binascii import hexlify
from collections import OrderedDict
from datetime import datetime
from io import StringIO
from logging.handlers import RotatingFileHandler
from threading import Thread, current_thread
import logging
import os
import sys
import threading
import time
import traceback

ROOT = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
VAR_FOLDER = os.path.join(ROOT, "var")

COLOR_LOGS = True
MAX_LOG_SIZE = 10485760
# number of bytes to leave after rotating/truncating a file
ROTATE_LEFT_OVER_BYTES = 3000
LOG_COUNT = 3

ROOT_HANDLER = None

if not os.path.exists(VAR_FOLDER):
    try:
        os.makedirs(VAR_FOLDER)
    except:
        pass


class LogManager(object):
    def __init__(self):
        self.lock = threading.RLock()
        self.master = None
        self.loggers = {}
        self.streams = {}

    def setMaster(self, logger):
        self.acquire()
        self.master = logger
        self.release()

    def getStream(self, filename, max_bytes=MAX_LOG_SIZE):
        if filename is None:
            filename = "stdout"
        self.acquire()
        stream = self.streams.get(filename)
        if not stream:
            stream = LoggerStream(filename, max_bytes)
            self.streams[filename] = stream
        self.release()
        return stream

    def getLogger(self, name):
        self.loggers.get(name, None)

    def addLogger(self, logger):
        self.acquire()
        self.loggers[logger.name] = logger
        self.release()

    def removeLogger(self, logger):
        if logger.name in self.loggers:
            self.acquire()
            if logger.name in self.loggers:
                del self.loggers["name"]
            self.release()

    def acquire(self):
        """
        Acquire the I/O thread lock.
        """
        if self.lock:
            self.lock.acquire()

    def release(self):
        """
        Release the I/O thread lock.
        """
        if self.lock:
            self.lock.release()


LOG_MANAGER = LogManager()


def getLogger(
    name="root",
    filename=None,
    debug=False,
    errors_to_root=True,
    set_master=False,
    max_bytes=MAX_LOG_SIZE,
    create_path=True,
):
    try:
        LOG_MANAGER.acquire()
        rest_logger = LOG_MANAGER.loggers.get(name, None)
        if rest_logger:
            if filename and not rest_logger.filename:
                rest_logger.setFilename(filename)
            LOG_MANAGER.release()
            return rest_logger
        level = Logger.INFO
        if debug:
            level = Logger.ALL
        #
        master = None
        if errors_to_root:
            master = LOG_MANAGER.master
        rest_logger = Logger(name, filename, level, master, max_bytes=max_bytes)
        LOG_MANAGER.loggers[name] = rest_logger
        if set_master:
            LOG_MANAGER.master = rest_logger
    except Exception as err:
        print(str(err))
        print(str(traceback.format_exc()))
    LOG_MANAGER.release()
    return rest_logger


def setupMasterLogger(name="root", filename=None, debug=False):
    hal_logger = getLogger(name, filename, debug, False, set_master=True)
    hal_logger.capture_stdout()
    hal_logger.capture_stderr()
    return hal_logger


LEVEL_NAMES = {
    "50": "CRITICAL",
    "40": "ERROR",
    "30": "WARNING",
    "20": "INFO",
    "10": "DEBUG",
    "0": "ALL",
}

LEVEL_COLORS = {"WARNING": "YELLOW", "DEBUG": "BLUE", "CRITICAL": "PINK", "ERROR": "YELLOW"}


class LoggerStream(object):
    def __init__(self, filename, max_bytes=MAX_LOG_SIZE):
        self.is_file = False
        self.filename = filename
        if filename:
            if filename not in ["stdout", "stderr"]:
                self.is_file = True
                # lets put it in the var path
                if not os.path.exists(self.filename):
                    path, fname = os.path.split(filename)
                    if not len(path):
                        self.filename = os.path.join(VAR_FOLDER, filename)
        self.max_bytes = max_bytes
        self.stream = None
        self.lock = threading.RLock()
        self.open()

    def open(self):
        if self.stream:
            try:
                # test if file is still open?
                self.stream.size()
                return
            except:
                self.stream = None

        if self.is_file:
            try:
                self.acquire()
                self.stream = open(self.filename, "a")
            finally:
                self.release()
        else:
            self.stream = sys.stdout

    def close(self):
        if self.stream:
            try:
                self.acquire()
                self.stream.close()
                self.stream = None
            finally:
                self.release()

    def flush(self):
        if self.stream:
            self.stream.flush()

    def write(self, data):
        if not self.stream:
            self.open()
        self.stream.write(data)
        self.stream.flush()

    def acquire(self):
        """
        Acquire the I/O thread lock.
        """
        if self.lock:
            self.lock.acquire()

    def release(self):
        """
        Release the I/O thread lock.
        """
        if self.lock:
            self.lock.release()

    def size(self):
        if not self.is_file:
            return 0
        pos = self.stream.tell()
        self.stream.seek(0, 2)
        size = self.stream.tell()
        self.stream.seek(pos)
        return size

    def clear(self):
        self.acquire()
        if self.stream:
            self.stream.close()
            self.stream = None
        self.stream = open(self.filename, "w")
        self.release()

    def rotate(self):
        # assume we are already locked?
        # simple way lets open the file for writing
        # read the last
        # reopen file for reading and writing
        self.close()
        to_end = ""
        with open(self.filename, "r") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            # now lets go back 3000 bytes and find first new line
            stream.seek(size - ROTATE_LEFT_OVER_BYTES)
            stream.readline()
            to_end = stream.read()
        self.stream = open(self.filename, "w")
        self.stream.write(to_end)
        self.stream.flush()

    def rotateCheck(self):
        if self.is_file and self.max_bytes > 0:  # are we rolling over?
            self.open()
            self.stream.seek(0, 2)  # due to non-posix-compliant Windows feature
            if self.size() >= self.max_bytes:
                return True
        return False

    def backup(self, filename=None):
        # backup the current logger to a backup file
        if not self.is_file:
            return False
        self.acquire()
        try:
            data = ""
            with open(self.filename, "r") as stream:
                data = stream.read()
            if not data:
                self.release()
                return False
            if filename is None:
                filename = self.filename + ".{}.backup".format(int(time.time()))
            path, fname = os.path.split(filename)
            if not len(path):
                filename = os.path.join(VAR_FOLDER, filename)
            with open(filename, "w") as backup_file:
                backup_file.write(data)
        except Exception as err:
            pass
        self.release()
        return True


class Logger(object):
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    ALL = 0

    def __init__(
        self,
        name,
        filename=None,
        level=20,
        master=None,
        master_level=30,
        fmt=None,
        color=COLOR_LOGS,
        max_bytes=MAX_LOG_SIZE,
    ):
        self.name = name
        self.filename = filename
        self.level = level
        self.master = master
        self.master_level = master_level
        self.color = color
        if fmt is None:
            fmt = "{asctime} {levelname} {name}({threadName}): {msg}"
        self._fmt = fmt
        self.max_bytes = max_bytes
        self.lock = threading.RLock()
        self.stream = None
        self.setFilename(self.filename)

    def setFilename(self, filename):
        self.filename = filename
        try:
            self.stream = LOG_MANAGER.getStream(self.filename, self.max_bytes)
        except Exception as err:
            print("ERROR")
            print(str(err))
            self.stream = LOG_MANAGER.getStream(None, self.max_bytes)
            print(str(err))
            self.error(err)

    def setLevel(self, level):
        self.level = level

    def capture_stdout(self):
        sys.stdout = self.stream.stream

    def capture_stderr(self):
        sys.stderr = self.stream.stream

    def emit(self, record):
        if record.level >= self.level:
            record.name = self.name
            line = self.format(record)
            try:
                self.stream.acquire()
                if self.stream.rotateCheck():
                    # we need to rotate the logs
                    self.stream.rotate()
                self.stream.write(line)
            finally:
                self.stream.release()
        if self.master and record.level >= self.master_level:
            self.master.emit(record)

    def format(self, record):
        out = self._fmt.format(**record)
        level_color = None
        if self.color:
            if record.color != None:
                level_color = record.color
            else:
                level_color = LEVEL_COLORS.get(record.levelname, None)
            if level_color:
                out = "{}{}{}".format(ConsoleColors.__dict__[level_color], out, ConsoleColors.OFF)
        if record.stack:
            if level_color:
                out = "\n{}\n{}{}{}".format(out, ConsoleColors.RED, record.stack, ConsoleColors.OFF)
            else:
                out = "{}\n{}".format(out, record.stack)
        return out + "\n"

    def log(self, level, args, stack=None, master_only=False, color=None):
        if level < self.level and level < self.master_level:
            return
        record = objict()
        record.name = self.name
        record.color = color
        record.asctime = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        record.level = level
        record.levelname = LEVEL_NAMES.get(str(level), str(level))
        record.threadName = current_thread().name
        record.stack = stack
        msg = []
        if type(args) in [list, tuple]:
            for arg in args:
                if isinstance(arg, dict) or isinstance(arg, list):
                    msg.append(prettyWriteToString(arg))
                else:
                    msg.append(str(arg))
            record.msg = "\n".join(msg)
        else:
            record.msg = args

        if master_only and self.master and level >= self.master_level:
            self.master.emit(record)
        else:
            self.emit(record)

    def insertLineBreak(self, count=1):
        self.stream.acquire()
        self.stream.write("\n" * count)
        self.stream.release()

    # gets overwritten by "master" attribute...
    # def master(self, level, *args):
    #     self.log(level, args, master_only=True)

    def info(self, *args, color=None):
        self.log(self.INFO, args)

    def debug(self, *args, color=None):
        self.log(self.DEBUG, args)

    def warning(self, *args, color=None):
        self.log(self.WARNING, args)

    def error(self, *args, color=None):
        self.log(self.ERROR, args)

    def critical(self, *args, color=None):
        self.log(self.CRITICAL, args)

    def exception(self, *args, color=None):
        self.log(self.ERROR, args, stack=traceback.format_exc())

    def backup(self, filename=None):
        self.stream.backup(filename)

    def __str__(self):
        output = self.filename
        if not output:
            output = "stdout"
        return "Logger<{} {}>".format(self.name, output)


class ColorFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None):
        if not fmt:
            fmt = "%(asctime)s - %(levelname)s - {YELLOW}%(name)s:%(threadName)s:{OFF} %(message)s".format(
                **ConsoleColors.__dict__
            )
        super(ColorFormatter, self).__init__(fmt, datefmt)

    def format(self, record):
        if record.levelname == "ERROR":
            return "\n{}{}{}\n".format(
                ConsoleColors.YELLOW, super(ColorFormatter, self).format(record), ConsoleColors.OFF
            )
        if record.levelname in LEVEL_COLORS:
            color = LEVEL_COLORS[record.levelname]
            record.levelname = "{}{}{}".format(ConsoleColors.__dict__[color], record.levelname, ConsoleColors.OFF)
        return super(ColorFormatter, self).format(record)

    def formatException(self, exc_info):
        return "{}{}{}".format(
            ConsoleColors.RED, super(ColorFormatter, self).formatException(exc_info), ConsoleColors.OFF,
        )


class BridgeLogFormatter(logging.Formatter):
    def format(self, record):
        return {
            "name": record.name,
            "message": record.msg,
            "asctime": record.asctime,
            "level": record.levelname,
            "func": record.funcName,
            "lineno": record.lineno,
            "pathname": record.pathname,
        }


from decimal import Decimal

PRETTY_INDENT = 4
PRETTY_MAX_VALUE_LENGTH = 6000
PRETTY_MAX_LINES = 100000
PRETTY_MAX_LENGTH = 500000


class ConsoleColors:
    if os.name == "nt":
        BLACK = ""
        RED = ""
        GREEN = ""
        YELLOW = ""
        PINK = ""
        BLUE = ""
        WHITE = ""

        HBLACK = ""
        HRED = ""
        HGREEN = ""
        HYELLOW = ""
        HBLUE = ""
        HPINK = ""
        HWHITE = ""

        HEADER = ""
        FAIL = ""
        OFF = ""
        BOLD = ""
        UNDERLINE = ""
    else:
        BLACK = "\033[30m"
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        PINK = "\033[35m"
        BLUE = "\033[34m"
        WHITE = "\033[37m"

        HBLACK = "\033[90m"
        HRED = "\033[91m"
        HGREEN = "\033[92m"
        HYELLOW = "\033[93m"
        HBLUE = "\033[94m"
        HPINK = "\033[95m"
        HWHITE = "\033[97m"

        HEADER = "\033[95m"
        FAIL = "\033[91m"
        OFF = "\033[0m"
        BOLD = "\033[1m"
        UNDERLINE = "\033[4m"


def prettyWriteToString(d):
    output = StringIO()
    prettyWrite(d, output, colors=True)
    out = output.getvalue()
    output.close()
    return out


def dictToString(d):
    output = StringIO()
    prettyWrite(d, output, colors=True)
    out = output.getvalue()
    output.close()
    return out


def prettyLog(msg, data, logger=None):
    if not logger:
        logger = getLogger("root")
    out = prettyWriteToString(data)
    logger.info("{}\n{}".format(msg, out))


def prettyPrint(msg, color=None):
    sys.stdout.write("{}{}{}".format(color, msg, ConsoleColors.OFF))
    sys.stdout.flush()


SANATIZE_KEYS = ["track1", "track2", "track3", "pan" "epb"]


def prettyWrite(d, f=None, indent=PRETTY_INDENT, banner=None, line_count=0, ignore_false=False, colors=True):
    std_output = False
    if f is None:
        std_output = True
        f = StringIO()

    if isinstance(d, dict):
        try:
            d = OrderedDict(sorted(d.items()))
        except:
            print("unabled to sort dict")
    prev = None
    if banner:
        f.write("---- BEGIN {} ----\n".format(banner))
    if type(d) is list:
        prev = False
        f.write("[")
        for i in d:
            if prev:
                line_count += 1
                f.write(",")
            else:
                line_count += 1
                # f.write('\n')
            flen = 0
            if hasattr(f, "len"):
                flen = f.len
            else:
                flen = f.tell()
            if line_count > PRETTY_MAX_LINES or flen >= PRETTY_MAX_LENGTH:
                f.write('{}"...truncated:PRETTY_MAX_LINES"'.format(" " * indent))
                break
            prev = True
            if type(i) is bool:
                i = int(i)
            if type(i) in [str, str]:
                if len(i) >= PRETTY_MAX_VALUE_LENGTH:
                    f.write(
                        '{}"{}...truncated:PRETTY_MAX_VALUE_LENGTH..."'.format(
                            " " * 1, i[: PRETTY_MAX_VALUE_LENGTH - 20]
                        )
                    )
                else:
                    f.write('{}"{}"'.format(" " * 1, i))
            elif type(i) is list or isinstance(i, dict):
                f.write(" " * (1))
                line_count = prettyWrite(i, f, indent + PRETTY_INDENT, line_count=line_count)
            elif type(i) is Decimal:
                f.write("{}{}".format(" " * 1, str(i)))
            else:
                f.write("{}{}".format(" " * 1, i))
        line_count += 1
        f.write("]")
    elif isinstance(d, dict):
        f.write("{")
        for key, value in list(d.items()):
            if ignore_false and not value:
                continue
            if prev:
                line_count += 1
                f.write(",\n")
            else:
                line_count += 1
                f.write("\n")

            if hasattr(f, "len"):
                flen = f.len
            else:
                flen = f.tell()
            if line_count > PRETTY_MAX_LINES or flen >= PRETTY_MAX_LENGTH:
                f.write('{}"truncated":"...truncated:PRETTY_MAX_LINES"\n'.format(" " * indent))
                break
            prev = True
            if type(key) in [str, str]:
                if colors:
                    f.write('{}{}"{}"{}:'.format(" " * indent, ConsoleColors.YELLOW, key, ConsoleColors.OFF))
                else:
                    f.write('{}"{}":'.format(" " * indent, key))
            else:
                f.write("{}{}: ".format(" " * indent, str(key)))
            if type(value) is list or isinstance(value, dict):
                f.write(" ")
                line_count = prettyWrite(value, f, indent + PRETTY_INDENT, line_count=line_count)
            else:
                if type(value) in [str, str]:
                    if key in SANATIZE_KEYS:
                        value = "{}:***{}".format(len(value), value[-4:])

                    if len(value) >= PRETTY_MAX_VALUE_LENGTH:
                        f.write(
                            ' "{}...truncated:PRETTY_MAX_VALUE_LENGTH"'.format(value[: PRETTY_MAX_VALUE_LENGTH - 20])
                        )
                    else:
                        if colors:
                            f.write(' {}"{}"{}'.format(ConsoleColors.GREEN, value, ConsoleColors.OFF))
                        else:
                            f.write(' "{}"'.format(value))
                elif type(value) in [datetime, time]:
                    if colors:
                        f.write(' {}"{}"{}'.format(ConsoleColors.GREEN, value, ConsoleColors.OFF))
                    else:
                        f.write(' "{}"'.format(value))
                elif type(value) is bool:
                    if colors:
                        if value:
                            f.write(" {}{}{}".format(ConsoleColors.GREEN, value, ConsoleColors.OFF))
                        else:
                            f.write(" {}{}{}".format(ConsoleColors.RED, value, ConsoleColors.OFF))
                    else:
                        f.write(" {}".format(value))
                elif type(value) is Decimal:
                    if colors:
                        f.write(" {}{}{}".format(ConsoleColors.BLUE, value, ConsoleColors.OFF))
                    else:
                        f.write(" {}".format(value))
                elif isinstance(value, bytearray):
                    f.write(" {}".format(str(bytes(hexlify(value)), encoding="utf-8")))
                else:
                    if colors:
                        f.write(" {}{}{}".format(ConsoleColors.RED, value, ConsoleColors.OFF))
                    else:
                        f.write(" {}".format(value))
        line_count += 1
        f.write("\n")
        f.write(" " * (indent - PRETTY_INDENT))
        f.write("}")
    else:
        f.write(str(d))

    if banner:
        f.write("\n---- END {} ----\n".format(banner))
    if indent == PRETTY_INDENT:
        f.write("\n")
    if std_output:
        sys.stdout.write(f.getvalue())
        f.close()
    return line_count

# short hand
pp = prettyWrite

def start_bridge_logger(bridges):
    logger = getLogger()
    logger.setLevel(logging.INFO)

    handler = LogToBridgeHandler()
    handler.bridges = bridges
    formatter = BridgeLogFormatter("root")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger, handler


class LogToBridgeHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        for device in self.bridges:
            # avoid recursion!
            try:
                device_path = os.path.abspath(sys.modules[device.__module__].__file__)
                if device_path.endwith("c"):
                    device_path = device_path[:-1]
                if os.path.basename(device_path) == os.path.basename(log_entry.get("pathname")):
                    continue
            except:
                pass
            device.on_proxy_event("hal", "log", log_entry)
        return True

