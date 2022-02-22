#!/usr/bin/env python3.8

import os
import sys
import signal

import time
from datetime import datetime, timedelta
from optparse import OptionParser

FILE = os.path.realpath(__file__)
ROOT=os.path.split(os.path.dirname(FILE))[0]
VAR_PATH=os.path.join(ROOT, "var")
PID_FILE = os.path.join(VAR_PATH, "tq_worker.pid")
RELOAD_FILE = os.path.join(ROOT, ".git", "FETCH_HEAD")
sys.path.append(os.path.join(ROOT, 'django'))
from service import Service


if os.path.exists("/opt/finspec") and "/opt/finspec" not in sys.path:
    sys.path.append("/opt/finspec")
    sys.path.append("/opt/mmemv")


class TaskQueueService(Service):
    def __init__(self):
        self.manager = None
        self.logger = None
        super(TaskQueueService, self).__init__("tq_worker", pid_file=PID_FILE, watch_file=RELOAD_FILE)

    def setup_options(self, parser):
        parser.add_option("-c", "--config", type="str", dest="config", default=None)
        parser.add_option("--catchsignal", dest="catchsignal", action="store_true")
        parser.add_option("--no-catchsignal", dest="catchsignal", action="store_false")
        parser.set_defaults(catchsignal=True)

    def on_restart_request(self):
        self.log("on_restart_request")
        self.shutdownManager()
        self.removePID()
        self.restart()

    def restart(self):
        try:
            self.closeOpenFiles()
        except Exception as e:
            self.log("restart failed?")
            self.log(e)
        cmd = sys.executable
        self.log("executing", cmd, sys.argv)
        os.execl(FILE, "start")


    def on_pre_stop(self, signum, frame):
        self.log("on_pre_stop")
        self.shutdownManager()
        sys.exit(0)

    def shutdownManager(self):
        if self.manager:
            self.log("start shutdown")
            try:
                self.manager.stop()
            except:
                pass
            self.log("shutdown complete")

    def on_run(self, opts, args):
        if opts.catchsignal:
            signal.signal(signal.SIGTERM, self.on_pre_stop)
            signal.signal(signal.SIGINT, self.on_pre_stop)

        os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
        import django
        django.setup()
        import version
        self.log("version: {}".format(version.VERSION))
        from taskqueue import worker
        from rest.log import getLogger
        logger = getLogger("root", filename="tq_worker.log")
        self.log("prepping tq_worker.log")
        # (opts, args) = parser.parse_args()
        if not opts.verbose:
            logger.capture_stdout()
            logger.capture_stderr()
            logger.info("stdout/stderr directed to file")
        else:
            logger = getLogger("no_logfile")
            logger.capture_stdout()
            logger.capture_stderr()

        if not worker.TQ_SUBSCRIBE:
            logger.info("missing models")
            return
        self.log("getting manager")
        self.manager = worker.WorkManager(service=self, logger=logger)
        try:
            self.manager.processBacklog()
            self.log("switching to tq_worker.log")
            logger.info("switched logging from service")
            self.logger = logger
            logger.info("running forever")
            self.log("running forever")
            self.manager.run_forever()
        except KeyboardInterrupt:
            logger.warning("keyboard interrupt")
            self.manager.stop()
        except Exception as err:
            self.log(str(err))
            logger.exception(err)

def main():
    service = TaskQueueService()
    service.log("lets get started....")
    service.run()

if __name__ == "__main__":
    main()