import functools
import sys
from . import log
import traceback
import threading
from datetime import datetime, timedelta
from objict import objict


SEQUENCE = 0
STOP_ON_FAIL = True
VERBOSE = True

logger = log.getLogger(filename="test.log")

TEST_RUN = objict(total=0, passed=0, failed=0, tests=objict())


class TestStopped(Exception):
    pass


def getDateRange(days=14, when=None):
    if when is None:
        when = datetime.now()
    start = when - timedelta(days=days)
    return start.strftime("%m/%d/%Y"), when.strftime("%m/%d/%Y")


def toString(value):
    if isinstance(value, bytes):
        value = value.decode()
    elif isinstance(value, bytearray):
        value = value.decode("utf-8")
    elif isinstance(value, (int, float)):
        value = str(value)
    return value


def toBytes(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    elif isinstance(value, bytearray):
        value = bytes(value)
    return value


def getNextSeq():
    global SEQUENCE
    if SEQUENCE == 0:
        from datetime import datetime
        now = datetime.now()
        SEQUENCE = int((now - now.replace(hour=0, minute=0,
                                          second=0, microsecond=0)).total_seconds())
    else:
        SEQUENCE += 1
    return SEQUENCE


def testValidDataResponse(resp):
    assert resp and resp.status and resp.data, "\t\t{red}assert failed:{off} {pink}'{err}{off}'".format(
        red=log.ConsoleColors.RED,
        pink=log.ConsoleColors.PINK,
        off=log.ConsoleColors.OFF,
        err=resp)


def testValidResponse(resp):
    if resp.status_code and resp.status_code != 200:
        raise AssertionError("{} HTTP Error".format(resp.status_code))
    assert resp and resp.status, "\t\t{red}assert failed:{off} {pink}'{err}{off}'".format(
        red=log.ConsoleColors.RED,
        pink=log.ConsoleColors.PINK,
        off=log.ConsoleColors.OFF,
        err=resp)


def assertErrorCode(resp, error_code):
    expectAssert(error_code, resp.error_code, "error_code")
    

def testAssert(exp, fail_msg=None):
    assert exp, "\t\t{red}assert failed:{off} {pink}'{err}{off}'".format(
        red=log.ConsoleColors.RED,
        pink=log.ConsoleColors.PINK,
        off=log.ConsoleColors.OFF,
        err=fail_msg)


def testCompareIn(val, val_list, name=None):
    assert val in val_list, "\t\t{red}assert failed:{off} {name} expected '{val_list}' but got '{val}'".format(
        red=log.ConsoleColors.RED,
        off=log.ConsoleColors.OFF,
        name=name, val_list=val_list, val=val)


def testCompare(str1, str2, fail_msg=None):
    debug_out = fail_msg
    if isinstance(str1, (str, bytes)):
        str1 = toString(str1)
        str2 = toString(str2)
        if str1 != str2:
            if not fail_msg:
                fail_msg = "string compare failed"
            is_on = False
            d1 = [log.ConsoleColors.OFF]
            d2 = [log.ConsoleColors.OFF]
            for i in range(0, len(str1)-1):
                out_range = i > (len(str1)-1) or i > (len(str2)-1)
                if out_range:
                    break
                if not is_on and (out_range or str1[i] != str2[i]):
                    is_on = True
                    d1.append(log.ConsoleColors.YELLOW)
                    d2.append(log.ConsoleColors.YELLOW)
                elif is_on and str1[i] == str2[i]:
                    is_on = False
                    d1.append(log.ConsoleColors.OFF)
                    d2.append(log.ConsoleColors.OFF)
                d1.append(str1[i])
                d2.append(str2[i])
            debug_out = "{}\nstr1:\n'{}'\nstr2:\n'{}'".format(
                fail_msg, "".join(d1), "".join(d2))
        assert str1 == str2, "\t\t{red}assert failed:{off}\n{err}".format(
            red=log.ConsoleColors.RED,
            off=log.ConsoleColors.OFF,
            err=debug_out)
    else:
        fail_msg = "{}: {} vs {} doesn't match".format(fail_msg, str1, str2)
        expectAssert(str1, str2, fail_msg)


def expectAssert(exp, got, name):
    assert exp == got, "\t\t{red}assert failed:{off} {name} expected '{exp}' but got '{got}'".format(
        red=log.ConsoleColors.RED,
        off=log.ConsoleColors.OFF,
        name=name, exp=exp, got=got)


def assertEqualToDict(exp, got, class_name):
    """
    Will take all the items and the dic and compare them
    to items in the obj or dict
    """
    for key, value in list(exp.items()):
        got_value = got.get(key, None)
        if got_value != value:
            raise AssertionError("{0}.{1} expected {2} == {3}".format(
                class_name, key, got_value, value))
    return True


def assertNotHasKeys(obj, keys, not_null=False):
    if type(keys) in [str, str]:
        keys = [keys]
    class_name = obj.__class__.__name__
    for key in keys:
        has_key = key in obj
        assert not has_key, "{0}.{1} found".format(class_name, key)


def unit_test(name=None):
    def actual_decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                TEST_RUN.total += 1
                nm = func.__name__
                if name:
                    nm = name
                elif "test_name" in kwargs:
                    nm = kwargs.get("test_name", nm)
                elif "test_fix" in kwargs:
                    nm = "{}_{}".format(nm, kwargs.get("test_fix"))
                sys.stdout.write("\t{}{}{}".format(
                    log.ConsoleColors.YELLOW, nm.ljust(60, '.'), log.ConsoleColors.OFF))
                sys.stdout.flush()
                out = func(*args, **kwargs)
                TEST_RUN.tests["{}:{}".format(TEST_RUN.tests.active_test, nm)] = True
                TEST_RUN.passed += 1
                sys.stdout.write(log.ConsoleColors.GREEN)
                sys.stdout.write("PASSED\n")
                sys.stdout.write(log.ConsoleColors.OFF)
                return out
            except AssertionError as err:
                TEST_RUN.failed += 1
                TEST_RUN.tests["{}:{}".format(TEST_RUN.tests.active_test, nm)] = False
                sys.stdout.write(log.ConsoleColors.RED)
                sys.stdout.write("FAILED\n")
                sys.stdout.write(log.ConsoleColors.OFF)
                if VERBOSE:
                    print((str(err)))
                if STOP_ON_FAIL:
                    raise TestStopped()
            except Exception:
                TEST_RUN.failed += 1
                TEST_RUN.tests["{}:{}".format(TEST_RUN.tests.active_test, nm)] = False
                sys.stdout.write(log.ConsoleColors.RED)
                sys.stdout.write("FAILED\n\n")
                if VERBOSE:
                    sys.stdout.write(traceback.format_exc())
                sys.stdout.write(log.ConsoleColors.OFF)
                if STOP_ON_FAIL:
                    raise TestStopped()
            return True
        return wrapper
    return actual_decorator


def asyncio():
    def actual_decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            t = threading.Thread(target=func, args=args, kwargs=kwargs)
            t.daemon = True
            t.start()
            return t
        return wrapper
    return actual_decorator


def assertHasKeys(obj, keys, not_null=False):
    if not hasattr(obj, "has_key"):
        return self.assertHasAttrs(obj, keys, not_null)
    if type(keys) in [str, str]:
        keys = [keys]
    class_name = obj.__class__.__name__
    for key in keys:
        has_key = key in obj
        if has_key and not_null:
            assert obj.get(key) != None, "{0}.{1} is None".format(
                class_name, key)
        assert has_key, "{0}.{1} not found".format(class_name, key)
