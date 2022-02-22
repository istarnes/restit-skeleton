#!/usr/bin/env python3.8
import os, sys
import subprocess

# test for pipenv
if "PIPENV_ACTIVE" not in os.environ and "VIRTUAL_ENV" not in os.environ:
    # we may not be using pipenv... check if we have django
    try:
        import django
        print("not using pipenv!!!")
    except:
        # we don't have django, and pipenv not active, lets attempt to rerun script in pipenv
        cmd = ["pipenv", "run"] + sys.argv
        print("attempting to run again via pipenv....")
        ecode = subprocess.check_call(cmd)
        exit(ecode)


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
ROOT=os.path.split(os.path.dirname( os.path.realpath( __file__ ) ))[0]

def validate(args):
    res = os.system(os.path.join(ROOT, "bin", "checkup.py"))
    if res:
        # tests failed
        sys.exit(res)

def test(args):
    cmd = "run_tests.py " + ' '.join(args)
    cmd = os.path.join(ROOT, "bin", cmd)
    print(cmd)
    res = os.system(cmd)
    if res:
        sys.exit(res)

def checkCanMigrate():
    # migration request special permission
    ROOT=os.path.split(os.path.dirname( os.path.realpath( __file__ ) ))[0]
    PROJECT_NAME = os.path.split(ROOT)[-1].upper()
    DJANGO_ROOT = os.path.join(ROOT, 'django')
    sys.path.append(DJANGO_ROOT)
    import django
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
    django.setup()
    from django.conf import settings
    if not getattr(settings, "CAN_MIGRATE", False):
        print("migration not allowed by settings")
        sys.exit(0)

if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    args = sys.argv[:]
    if len(args) > 1:
        if args[1] == 'validate':
            validate(args[1:])
        elif args[1] == "run":
            args[1] = "runserver"
        elif args[1] == "runserver":
            pass # validate()
        elif args[1] == "test":
            test(args[1:])
            sys.exit(0)
        elif args[1] == "migrate":
            checkCanMigrate()
    execute_from_command_line(args)
