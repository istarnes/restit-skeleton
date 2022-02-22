#!/usr/bin/env python3.8

#
# Periodic maintenance script
#  * runs through the run_* functions in each app/periodic.py
#
# to run a function manually, run:
# ./bin/periodic.py --app=YOUR_APP_NAME --method=METHOD_NAME (without run_) --force --verbose

import os
import sys
import signal

import time
from datetime import datetime, timedelta
from optparse import OptionParser

ROOT=os.path.split(os.path.dirname( os.path.realpath( __file__ ) ))[0]
VAR_PATH=os.path.join(ROOT, "var")

LOG_FILE=os.path.join(VAR_PATH, "periodic.log")
PID_FILE = os.path.join(VAR_PATH, ".periodic_pid")
# PID_FILE = os.path.join(VAR_PATH, ".periodic_pid")
sys.path.append(os.path.join(ROOT, 'django'))

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

import django
django.setup()

from django.conf import settings

from account.models import *
from rest import helpers
from rest import RemoteEvents
from rest import log
import traceback

import socket
hostname = socket.gethostname()


log.mkdir(VAR_PATH)
logger = log.getLogger(filename=LOG_FILE, set_master=True)

parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False )
parser.add_option("-f", "--force", action="store_true", dest="force", default=False )
parser.add_option("-u", "--user", type="str", dest="user", default="nobody" )
parser.add_option("-a", "--app", type="str", dest="app", default=None )
parser.add_option("-m", "--method", type="str", dest="method", default=None )
parser.add_option("-n", "--now", type="str", dest="now", default=None )
parser.add_option("-s", "--seq", type="str", dest="seq", default=None )
parser.add_option("--test", action="store_true", dest="test", default=False )
parser.add_option("--kill", action="store_true", dest="kill", default=False )
parser.add_option("-l", "--list", action="store_true", dest="list", default=False )

ROOT = os.path.dirname(settings.ROOT)

DEFAULT_WATCHDOG_SETTINGS = {
    "memory": {
        "load": 90,
        "action": "touch {}/.git/index".format(ROOT)
    },
    "cpu": {
        "load": 90,
        "action": "touch {}/.git/index".format(ROOT)
    }
}

RUN_WATCHDOG = getattr(settings, "RUN_WATCHDOG", True)
WATCHDOG_SETTINGS = getattr(settings, "WATCHDOG_SETTINGS", DEFAULT_WATCHDOG_SETTINGS)
psutil = None
if RUN_WATCHDOG:
    import psutil

RUN_LOG_PRUNE = getattr(settings, "RUN_LOG_PRUNE", True)


def purge(dir, pattern):
    for f in os.listdir(dir):
        if f.startswith(pattern):
            if not f.endswith(".log"):
                os.remove(os.path.join(dir, f))


def pruneLogs(opts):
    now = datetime.now()
    if now.hour == 3 and now.minute < 4:
        purge(VAR_PATH, "django.log.")
        purge(VAR_PATH, "event.log.")


class Process(object):
    def __init__(self, pid_file=PID_FILE):
        self.pid_file = pid_file
        self.pid = self._readPID()

    def isRunning(self):
        if self.pid == 0:
            return False
        if os.path.exists("/proc/{}".format(self.pid)):
            return True
        return self._kill(0)

    def wait(self, timeout=30, do_kill=False):
        stale = time.time() + timeout
        time.sleep(1.0)
        while self.isRunning() and time.time() < stale:
            time.sleep(1.0)
            if do_kill:
                self._kill(signal.SIGKILL)
        return not self.isRunning()

    def terminate(self, force=True, timeout=30):
        if not self.isRunning():
            return False
        self._kill(signal.SIGTERM)
        self.wait(timeout, force)


    def _kill(self, signal=0):
        try:
            os.kill(self.pid, signal)
        except OSError:
            return False
        return True

    def _readPID(self):
        if os.path.exists(self.pid_file):
            try:
                with open(self.pid_file, mode='r') as f:
                    return int(f.read().strip())
            except:
                pass
        return 0

    def savePID(self):
        try:
            with open(self.pid_file, mode='w') as f:
                f.write(str(os.getpid()))
        except:
            pass

    def deletePID(self):
        try:
            os.remove(self.pid_file)
        except:
            logger.info("failed to delete pid file")


def getListOfProcessSortedByMemory():
    '''
    Get list of running process sorted by Memory Usage
    '''
    listOfProcObjects = []
    # Iterate over the list
    for proc in psutil.process_iter():
       try:
           # Fetch process details as dict
           pinfo = proc.as_dict(attrs=['pid', 'name', 'username', 'cpu_percent'])
           pinfo['vms'] = proc.memory_info().vms / (1024 * 1024)
           # Append dict to list
           listOfProcObjects.append(pinfo);
       except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
           pass

    # Sort list of dict by key vms i.e. memory usage
    listOfProcObjects = sorted(listOfProcObjects, key=lambda procObj: procObj['vms'], reverse=True)

    return listOfProcObjects

def sendMail(subject, msg, from_addr, to_list, fail_silently=False):
    from django.core.mail import send_mail
    send_mail(subject, msg, from_addr, to_list, fail_silently=fail_silently)

def watchDogAlarm(cmd, subject):
    logger.info(subject)
    logger.info("executing action: {}".format(cmd))
    cpu_load = psutil.cpu_percent()
    mem_load = psutil.virtual_memory().percent
    if cmd != "notify":
        os.system(cmd)
    logger.info("waiting for recovery...")
    time.sleep(10.0)
    msg = "host: {}\ncpu: {}\nmemory: {}\n".format(hostname, cpu_load, mem_load)
    cpu_load = psutil.cpu_percent()
    mem_load = psutil.virtual_memory().percent
    logger.info("checking recovery")
    msg += "watch dog action: {}\ncpu: {}\nmemory: {}\n".format(cmd, cpu_load, mem_load)
    procs = getListOfProcessSortedByMemory()[:20]
    output = []
    for proc in procs:
        output.append("{pid:8}{name:10}{username:8}{vms:>8} mb{cpu_percent:>6}%".format(**proc))
    sendMail(subject, "{}\n\npid     username       mem     cpu\n{}".format(msg, "\n".join(output)), settings.DEFAULT_FROM_EMAIL, ["support@311labs.com"])
    time.sleep(5.0)
    sys.exit(0)

def watchdogMemory(target, action=None):
    mem = psutil.virtual_memory()
    if mem.percent > target:
        msg = "({}) memory alarm target {} hit with {}".format(hostname, target, mem.percent)
        if action:
            watchDogAlarm(action, msg)
        else:
            logger.info(msg)
        return mem.percent
    return 0

def watchdogCPU(target, action=None):
    if action is None:
        cpu_load = psutil.cpu_percent(interval=2.0)
    else:
        cpu_load = psutil.cpu_percent()
    logger.info("cpu load: {}".format(cpu_load))
    if cpu_load > target:
        msg = "({}) cpu alarm target {} hit with {}".format(hostname, target, cpu_load)
        if action:
            time.sleep(4.0)
            cpu_load = psutil.cpu_percent()
            if cpu_load > target:
                watchDogAlarm(action, msg)
        else:
            logger.info(msg)
        return cpu_load
    return 0

def watchdog(opts):
    if not psutil:
        logger.info("cannot run watchdog without psutil")
        return
    mem_settings = WATCHDOG_SETTINGS.get("memory", None)
    if mem_settings:
        load = watchdogMemory(mem_settings["load"])
        if load:
            time.sleep(10.0)
            watchdogMemory(mem_settings["load"], mem_settings["action"])

    cpu_settings = WATCHDOG_SETTINGS.get("cpu", None)
    if cpu_settings:
        load = watchdogCPU(cpu_settings["load"])
        if load:
            logger.info("cpu under load!, confirming....")
            time.sleep(5.0)
            load = watchdogCPU(cpu_settings["load"])
            if load:
                logger.info("cpu still under load!")
                time.sleep(30.0)
                watchdogCPU(cpu_settings["load"], cpu_settings["action"])

def notifyError(app_name, func_name, error):
    try:
        stack = str(traceback.format_exc())
        subject = "periodic error {}.{}.{}".format(hostname, app_name, func_name)
        body = "{}.{}<br>\n{}<br>\n{}".format(app_name, func_name, str(error), stack)
        Member.notifyWithPermission("rest_errors", subject, message=body, email_only=True)
    except Exception as err:
        logger.error(err)

def runApp(app_name, show_list=False, now=None, opts=None):
    try:
        module = __import__(app_name + '.periodic', globals(), locals(), ['*'])
    except ImportError as err:
        notifyError(app_name, "import", err)
        if opts.verbose:
            logger.exception(err)
        return

    if opts.method:
        func = "run_{0}".format(opts.method)
        if hasattr(getattr(module, func, None), '__call__'):
            getattr(module, func)(force=opts.force, verbose=opts.verbose, now=now)
        return True

    for func in dir(module):
        if func[:4] == 'run_' and hasattr(getattr(module, func, None), '__call__'):
            if show_list:
                logger.info("\t{}".format(func))
                continue
            if opts.verbose:
                getattr(module, func)(force=opts.force, verbose=opts.verbose, now=now)
            else:
                try:
                    started = time.time()
                    resp = getattr(module, func)(force=opts.force, verbose=opts.verbose, now=now)
                    if resp != -22:
                        # -22 is the periodic no run res
                        logger.info("{}.{} - {}s".format(app_name, func, int(time.time() - started)))
                except Exception as err:
                    notifyError(app_name, func, err)
                    logger.exception(err)

def runAppList(apps, opts, now):
    proc = Process()
    if proc.pid:
        logger.info("found pid: {}".format(proc.pid))
        logger.info("is running: {}".format(proc.isRunning()))
    else:
        logger.info("no pid found")
    if proc.isRunning():
        # kill old periodic if still running
        logger.warning("existing periodic process({} vs {}) already running, terminating process...".format(proc.pid, os.getpid()))
        Member.notifyWithPermission("rest_errors", "periodic@{} terminated".format(hostname), message="warning a previous periodic job was still running at host: {}".format(hostname), email_only=True)
        proc.terminate(timeout=10.0)
        if proc.isRunning():
            logger.warning("failed to kill proc")
        else:
            logger.warning("proc killed")
    # save current pid to file
    proc.savePID()
    for name in apps:
        if "." not in name:
            runApp(name, False, now, opts)
    logger.info("total run time: {}s".format(int(time.time() - opts.started)))
    # delete current pid file
    proc.deletePID()

def runFor(opts, now):
    opts.started = time.time()
    if opts.list:
        for name in settings.PERIODIC_APPS:
            logger.info(name)
            runApp(name, True, now, opts)
        logger.info("total run time: {}s".format(int(time.time() - opts.started)))
        sys.exit(0)
    if opts.app:
        runApp(opts.app, False, now, opts)
        logger.info("total run time: {}s".format(int(time.time() - opts.started)))
    elif hasattr(settings, "PERIODIC_APPS"):
        # this is where we need to check if an existing periodic is running
        runAppList(settings.PERIODIC_APPS, opts, now)
    else:
        runAppList(helpers.getAppNames(), opts, now)

def main(opts, args):
    if opts.user:
        try:
            import pwd
            import os
            import errno
            uid = pwd.getpwnam(opts.user).pw_uid
            os.seteuid(uid)
        except KeyError:
            logger.warning("No such user: %s" % opts.user)
            pass
        except OSError as exc:
            if exc.errno == errno.EPERM:
                pass
            else:
                raise

    if opts.now is None:
        now = datetime.now()
    else:
        now = helpers.parseDate(opts.now)

    if opts.seq:
        if "h" in opts.seq:
            hours = int(opts.seq.replace('h', ''))
            for i in range(0, hours):
                now = now - timedelta(hours=i)
                runFor(opts, now)
        elif "m" in opts.seq:
            minutes = int(opts.seq.replace('m', ''))
            for i in range(0, minutes):
                now = now - timedelta(minutes=i)
                runFor(opts, now)
        elif "d" in opts.seq:
            days = int(opts.seq.replace('d', ''))
            for i in range(0, days):
                now = now - timedelta(days=i)
                runFor(opts, now)
    else:
        runFor(opts, now)

if __name__ == '__main__':
    (opts, args) = parser.parse_args()
    if not opts.verbose:
        logger.capture_stdout()
        logger.capture_stderr()
        logger.info("stdout/stderr directed to file")
    else:
        logger = log.getLogger("no_logfile")
        logger.capture_stdout()
        logger.capture_stderr()
    print(("logger path: {}".format(logger.stream.filename)))
    logger.info("periodic running")
    if opts.test or opts.kill:
        proc = Process()
        if proc.pid:
            logger.info("found pid: {}".format(proc.pid))
            logger.info("is running: {}".format(proc.isRunning()))
            if opts.kill:
                logger.warning("killing running periodic")
                proc.terminate()
                if proc.isRunning():
                    logger.warning("failed to kill proc")
                else:
                    logger.warning("proc killed")
        else:
            logger.info("no pid found")
        sys.exit(0)
    if RUN_WATCHDOG:
        watchdog(opts)
    if RUN_LOG_PRUNE:
        pruneLogs(opts)
    # print(("logger path: {}".format(logger.stream.filename)))
    main(opts, args)


