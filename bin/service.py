#!/usr/bin/env python3.8

import datetime
import os
import signal
import sys
import time

from optparse import OptionParser
from subprocess import check_output, getoutput

# import pwd

try:
    import psutil
except:
    psutil = None

import getpass

if hasattr(os, "devnull"):
    REDIRECT_TO = os.devnull
else:
    REDIRECT_TO = "/dev/null"

UMASK = 0
MAXFD = 1024
WORKDIR = "/"


try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except:
    Observer = None
    FileSystemEventHandler = object
    print("watchdog not installed")

def isPosix():
    return os.name == "posix"


def getPidsFor(name):
    return list(map(int, check_output(["pidof", name]).split()))


def getPidsWith(name):
    pids = []
    for p in psutil.process_iter(attrs=["cmdline", "name"]):
        if "python" in p.info["name"]:
            for c in p.info["cmdline"]:
                if name in c:
                    pids.append(p.pid)
    return pids


class Service(FileSystemEventHandler):
    def __init__(self, name, pid_file, description=None, require_user=None, watch_file=None, logger=None):
        self.name = name
        self.pid_file = pid_file
        self.pid = None
        self.require_user = require_user
        self.watch_file = None
        self.is_watching = False
        self.is_closing = False
        if watch_file:
            self.watch_file = os.path.realpath(watch_file)
        self.logger = logger

    def log(self, *args):
        if self.logger:
            self.logger.info(*args)

    def on_modified(self, event):
        if self.is_watching:
            self.log("file modified...{}".format(event.src_path))
            if self.watch_file == event.src_path:
                self.is_watching = False
                self.observer.stop()
                self.on_restart_request()

    def on_restart_request(self):
        self.log("attempting to restart")
        self.restart()

    def getUsername(self):
        # return os.getlogin()
        # return pwd.getpwuid(os.getuid())[0]
        return getpass.getuser()


    def showLog(self, lines=20):
        MAX_CHARS_PER_LINE = 80
        size_of_file = os.path.getsize(self.log_file)
        with open(self.log_file, "r") as f:
            seek_index = max(0, size_of_file - (lines * MAX_CHARS_PER_LINE))
            f.seek(seek_index)
            print((f.read()))

    def checkPidByName(self, pid):
        filename = os.path.basename(sys.argv[0])
        pids = getPidsFor(filename)
        return pid in pids

    def killOthers(self, my_pid=None):
        if my_pid is None:
            my_pid = psutil.Process().pid
        filename = os.path.basename(sys.argv[0])

        pids = getPidsWith(filename)
        for pid in pids:
            if pid != my_pid:
                self.log("kill {} my_pid: {}".format(pid, my_pid))
                self.kill(pid)

    def isRunning(self):
        my_pid = psutil.Process().pid
        filename = os.path.basename(sys.argv[0])
        pids = getPidsWith(filename)
        for pid in pids:
            if pid != my_pid:
                self.pid = pid
                return True
        return False

    def isRunningOld(self):
        self.getPID()
        if not self.pid:
            # check by name
            return False
        try:
            os.kill(self.pid, 0)  # or signal.SIGKILL
            return True
        except OSError as err:
            # might not have permissions
            return self.checkPidByName(self.pid)
        return False

    def savePID(self, pid):
        self.pid = pid
        self.log("PID FILE: {}".format(self.pid_file))
        with open(self.pid_file, "w") as f:
            f.write("{}".format(self.pid))

    def removePID(self):
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)

    def getPID(self):
        if os.path.exists(self.pid_file):
            with open(self.pid_file, "r") as f:
                self.pid = f.read()
                if self.pid.isdigit():
                    self.pid = int(self.pid)
        return self.pid

    def daemonized(self, pid, opts, args):
        os.chdir(WORKDIR)
        os.umask(UMASK)
        import resource  # Resource usage information.

        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY:
            maxfd = MAXFD
        # Iterate through and close all file descriptors.
        for fd in range(0, maxfd):
            try:
                os.close(fd)
            except OSError:  # ERROR, fd wasn't open to begin with (ignored)
                pass

        # This call to open is guaranteed to return the lowest file descriptor,
        # which will be 0 (stdin), since it was closed above.
        os.open(REDIRECT_TO, os.O_RDWR)  # standard input (0)

        # Duplicate standard input to standard output and standard error.
        os.dup2(0, 1)  # standard output (1)
        os.dup2(0, 2)  # standard error (2)

    def background(self, opts, args):
        fpid = os.fork()
        if fpid == 0:
            os.setsid()
            pid = os.fork()
            if pid == 0:
                self.pid = pid
                self.daemonized(pid, opts, args)
                return True
        os._exit(0)

    def start(self, opts, args, fork):
        if fork:
            fpid = os.fork()
            if fpid == 0:
                os.setsid()
                pid = os.fork()
                if pid == 0:
                    self.pid = pid
                    self.daemonized(pid, opts, args)
                    self.on_pre_run(opts, args)
                    self.on_run(opts, args)
                    sys.exit(0)
                self.savePID(pid)
                os._exit(0)
        else:
            self.on_pre_run(opts, args)
            self.on_run(opts, args)

    def terminate(self, pid):
        try:
            os.kill(pid, signal.SIGTERM)  # or signal.SIGKILL
            for i in range(0, 10):
                time.sleep(1.0)
                if not self.isRunning():
                    break
        except OSError as err:
            pass
        return not self.isRunning()

    def closeOpenFiles(self):
        self.log("closing open files")
        self.is_closing = True
        if psutil:
            p = psutil.Process(os.getpid())
            if hasattr(p, "open_files"):
                for handler in p.open_files() + p.connections():
                    os.close(handler.fd)

    def restart(self):
        try:
            self.closeOpenFiles()
        except Exception as e:
            self.log("restart failed?")
            self.log(e)
        cmd = sys.executable
        self.log("executing", cmd, sys.argv)
        os.execl(cmd, "python", *sys.argv)

    def kill(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)  # or signal.SIGKILL
            for i in range(0, 10):
                time.sleep(1.0)
                if not self.isRunning():
                    break
                self.log("still running")
        except OSError as err:
            self.log("failed to kill process?? '{}'".format(str(err)))
        return not self.isRunning()

    def stop(self):
        pid = self.getPID()
        if not self.pid:
            return
        self.terminate(pid)
        time.sleep(1.0)
        self.killOthers()
        self.removePID()
        return True

        # pid = self.getPID()
        # if not self.pid:
        #     return
        # is_dead = self.terminate(pid)
        # if not is_dead:
        #     is_dead = self.kill(pid)

        # if is_dead and os.path.exists(self.pid_file):
        #     os.remove(self.pid_file)

    def watchForKeyInt(self):
        signal.signal(signal.SIGINT, self.on_pre_stop)

    def watchForSignal(self, signum=signal.SIGTERM):
        signal.signal(signum, self.on_pre_stop)

    # override
    def on_pre_stop(self, signum, frame):
        self.log("interrupt caught???")
        sys.exit(1)

    def setup_options(self, parser):
        # parser.add_option("--port", type="int", dest="port", default=SERVER_PORT )
        # parser.add_option("--host", type="str", dest="host", default=SERVER_IP )
        # parser.add_option("--color", type="str", dest="color", default=None )
        pass

    def run(self):
        from optparse import OptionParser

        parser = OptionParser()
        parser.add_option("-n", "--noserver", action="store_true", dest="noserver", default=False)
        parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)
        parser.add_option("-f", "--force", action="store_true", dest="force", default=False)
        parser.add_option(
            "-b", "--background", action="store_true", dest="background", default=False
        )
        parser.add_option("-d", "--delay", type="int", dest="delay", default=0)

        parser.add_option("-u", "--action", type="str", dest="action", default=None)
        parser.add_option("--pidfile", type="str", dest="pid_file", default=None)
        self.setup_options(parser)
        opts, args = parser.parse_args()
        if len(args) > 0:
            opts.action = args[0]

        if opts.background:
            self.background(opts, args)
        self.main(opts, args)

    def checkUser(self):
        if self.require_user:
            cuser = self.getUsername()
            if self.require_user != cuser:
                self.log(("requires user '{}' but running as '{}".format(self.require_user, cuser)))
                return False
        return True

    def main(self, opts, args):
        if opts.delay:
            time.sleep(opts.delay)

        if opts.action == "start":
            if not self.checkUser():
                sys.exit(1)

            if self.isRunning():
                pid = self.getPID()
                self.log("already running {}".format(pid))
                self.savePID(pid)
                sys.exit(1)
            sys.stdout.write("starting {}: ".format(self.name))
            sys.stdout.flush()
            self.start(opts, args, fork=isPosix())
        elif opts.action == "stop":
            if not self.checkUser():
                sys.exit(1)
            sys.stdout.write("stopping {}: ".format(self.name))
            sys.stdout.flush()
            if not self.isRunning():
                self.log("already stopped")
                return
            self.stop()
            time.sleep(2.0)
            if self.isRunning():
                self.log("still running {}".format(self.getPID()))
            else:
                self.log("stopped")
        elif opts.action == "status":
            if self.isRunning():
                self.log("{} is: running {}".format(self.name, self.pid))
            else:
                self.log("{} is: off".format(self.name))
        elif opts.action == "restart":
            if not self.checkUser():
                sys.exit(1)
            sys.stdout.write("restarting {}: ".format(self.name))
            sys.stdout.flush()
            if self.isRunning():
                self.log("killing {}".format(self.pid))
                self.stop()
                time.sleep(2.0)
            self.log("starting... ")
            self.start(opts, args, fork=isPosix())
            for i in range(0, 10):
                time.sleep(1.0)
                if self.isRunning():
                    self.log("running {}".format(self.getPID()))
                    sys.exit(0)
            self.log("failed")

        elif opts.action == "log":
            self.showLog()
        else:
            if not self.checkUser():
                sys.exit(1)
            self.on_pre_run(opts, args)
            self.on_run(opts, args)

    def on_pre_run(self, opts, args):
        if self.watch_file and Observer:
            self.log("watching file: {}".format(self.watch_file))
            self.observer = Observer()
            path = os.path.dirname( self.watch_file )
            self.observer.schedule(self, path=path, recursive=False)
            self.is_watching = True
            self.observer.start()
        else:
            self.log("not watching file")

    def on_run(self, opts, args):
        pass
