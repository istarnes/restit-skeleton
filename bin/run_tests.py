#!/usr/bin/env python3.8

#
# test script
#  * runs through tests in each test/<module_name>/<test_name>.py
#

import json
import time
from datetime import datetime
from optparse import OptionParser
import traceback
import os
import sys

FILENAME = os.path.basename(__file__)
MODULE_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, MODULE_PATH)


from test import helpers
from test import log


parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true",
                  dest="verbose", default=False)
parser.add_option("-f", "--force", action="store_true",
                  dest="force", default=False, help="force the test to run now")
parser.add_option("-u", "--user", type="str", dest="user",
                  default="nobody", help="specify the user the test should run as")
parser.add_option("-m", "--module", type="str", dest="module",
                  default=None, help="run only this app/module")
parser.add_option("--method", type="str", dest="method",
                  default=None, help="run only this app/module")
parser.add_option("-t", "--test", type="str", dest="test",
                  default=None, help="specify a specify test method to run")
parser.add_option("-q", "--quick", action="store_true", dest="quick",
                  default=False, help="run only tests flagged as critical/quick")
parser.add_option("-x", "--extra", type="str", dest="extra",
                  default=None, help="specify extra data to pass to test")
parser.add_option("-l", "--list", action="store_true",
                  dest="list", default=False)
parser.add_option("-s", "--stop", action="store_true", dest="stop_on_errors", default=False)
parser.add_option("-e", "--errors", action="store_true", dest="show_errors", default=False, help="show errors")
parser.add_option("--host", type="str", dest="host",
                  default="http://localhost:8000/", help="specify host")
parser.add_option("--email", action="store_true", dest="email",
                  default=False, help="Email Test Results to Subscribers")


(opts, args) = parser.parse_args()

helpers.VERBOSE = opts.show_errors or opts.verbose
helpers.STOP_ON_FAIL = opts.stop_on_errors

if opts.verbose:
    print("verbose mode will log to files in var/")

if len(args) > 0:
    opts.module = args[0]

if opts.module and "." in opts.module:
    fields = opts.module.split('.')
    opts.module = fields[0]
    opts.test = fields[1]
    if len(fields) > 2:
        opts.method = fields[2]

if len(args) > 1:
    opts.test = args[1]

if opts.user:
    try:
        import pwd
        import os
        import errno
        uid = pwd.getpwnam(opts.user).pw_uid
        os.seteuid(uid)
    except KeyError:
        print("No such user: %s" % opts.user)
        pass
    except OSError as exc:
        if exc.errno == errno.EPERM:
            pass
        else:
            raise

now = datetime.now()
print("python: {}".format(sys.version))


def runTest(module, func_name, module_name, test_name, now):
    test_key = "{0}.{1}.{2}".format(module_name, test_name, func_name)
    print("--- RUNNING TESTS: {} ---".format(test_key))
    helpers.TEST_RUN.tests.active_test = test_key.replace(".", ":")
    started = time.time()
    if not opts.stop_on_errors:
        try:
            getattr(module, func_name)(opts)
        except Exception as err:
            if opts.verbose:
                print(str(err))
    else:
        try:
            getattr(module, func_name)(opts)
        except helpers.TestStopped as err:
            if opts.verbose:
                print(str(err))

    duration = time.time() - started
    print("\nrun time: {0:.2f}s".format(duration))
    return True


def runModuleTests(module_name, test_name):
    try:
        name = "test.{}.{}".format(module_name, test_name)
        module = __import__(name, globals(), locals(), ['*'])
    except ImportError:
        print('--------------')
        print("failed to import: " + name)
        print('--------------')
        traceback.print_stack()
        print('--------------')
        traceback.print_exc()
        return

    prefix = "run_" if not opts.quick else "quick_"
    plen = len(prefix)
    now = datetime.now()
    if opts.method:
        func_name = "{0}{1}".format(prefix, opts.method)
        if hasattr(getattr(module, func_name, None), '__call__'):
            return runTest(module, func_name, module_name, test_name, now)
        return True
    elif opts.list:
        print("")
        print(name)
        for func_name in dir(module):
            if func_name[:plen] == prefix and hasattr(getattr(module, func_name, None), '__call__'):
                print("\t" + func_name)
                # runTest(module, func_name, module_name, now)
        return True

    for func_name in dir(module):
        if func_name[:plen] == prefix and hasattr(getattr(module, func_name, None), '__call__'):
            runTest(module, func_name, module_name, test_name, now)


def runModule(module_name):
    mpath = os.path.join(os.path.join(MODULE_PATH), "test", module_name)
    tests = [f for f in os.listdir(mpath) if os.path.isfile(os.path.join(mpath, f)) and f != "__init__.py" and f.endswith(".py")]
    tests.sort()
    for name in tests:
        runModuleTests(module_name, name.split('.')[0])   


def main():
    if opts.module and opts.test:
        runModuleTests(opts.module, opts.test)
    elif opts.module:
        # list python files
        runModule(opts.module)
    else:
        mpath = os.path.join(os.path.join(MODULE_PATH), "test")
        tests = [f for f in os.listdir(mpath) if os.path.isdir(os.path.join(mpath, f))]
        tests.sort()
        # print(tests)
        for name in tests:
            runModule(name)
    print("=" * 80)
    log.prettyPrint("TOTAL RUN: {}\t".format(helpers.TEST_RUN.total), log.ConsoleColors.YELLOW)
    log.prettyPrint("TOTAL PASSED: {}\n".format(helpers.TEST_RUN.passed), log.ConsoleColors.GREEN)
    if helpers.TEST_RUN.failed > 0:
        log.prettyPrint("TOTAL FAILED: {}\n".format(helpers.TEST_RUN.failed), log.ConsoleColors.RED)

    print("=" * 80)
    helpers.TEST_RUN.save(os.path.join(log.VAR_FOLDER, "test_results.json"))

    if opts.email:
        attch = mail.makeAttachment("test_results.json", json.dumps(helpers.TEST_RUN, indent=4))
        body = "TOTAL RUN: {}\nTOTAL PASSED: {}\nTOTAL Failed: {}\n".format(helpers.TEST_RUN.total, helpers.TEST_RUN.passed, helpers.TEST_RUN.failed)
        if helpers.TEST_RUN.failed == 0:
            subject = "ALL TESTS PASS - {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
        else:
            subject = "TEST FAILURE - {}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
        mail.send(mail.SUBSCRIBERS, subject, body=body, attachments=[attch])

    if helpers.TEST_RUN.failed > 0:
        sys.exit("failed")


if __name__ == '__main__':
    main()


