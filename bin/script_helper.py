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

from datetime import datetime, timedelta
import django
import traceback
import requests

ROOT=os.path.split(os.path.dirname( os.path.realpath( __file__ ) ))[0]
PROJECT_NAME = os.path.split(ROOT)[-1].upper()
DJANGO_ROOT = os.path.join(ROOT, 'django')
sys.path.append(DJANGO_ROOT)
VER_FILE = os.path.join(DJANGO_ROOT, "version.py")
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")

from rest import UberDict

def fixVersion():
    major, minor, rev = getVersion()
    # print("major={0}\nminor={1}\nrev={2}\n".format(major, minor, rev))
    if major >= 0:
        saveVersion(major, minor, rev)

def getVersion():
    vmaj = -1
    vmin = -1
    vrev = -1
    with open(VER_FILE, 'r') as f:
        for line in f.readlines():
            if line.startswith("major"):
                vmaj = int(line.split('=')[1].strip())
            elif line.startswith("minor"):
                vmin = int(line.split('=')[1].strip())
            elif line.startswith("rev"):
                vrev = int(line.split('=')[1].strip())
                break
    return vmaj, vmin, vrev

def saveVersion(major, minor, rev):
    with open(VER_FILE, 'w') as f:
        f.write("major={0}\nminor={1}\nrev={2}\n".format(major, minor, rev))
        f.write('VERSION="{0}.{1}.{2}".format(major, minor, rev)\n')

try:
    import version
except:
    fixVersion()
    import version

has_settings = False
settings = None

def initDJANGO():
    global has_settings
    global settings
    if not has_settings:
        os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
        django.setup()
        from django.conf import settings
        has_settings = True
    return True

def sendMail(subject, msg, from_addr, to_list, fail_silently=False):
    initDJANGO()
    from django.core.mail import send_mail
    printYellow("sending message to: {}".format(to_list))
    send_mail(subject, msg, from_addr, to_list, fail_silently=fail_silently)
    printGreen("sent!")

def getUser(username):
    from account.models import User
    return User.objects.filter(username=username).last()

def logoutUser(username):
    user = getUser(username)
    if user is None:
        print("user: '{}' was not found", username)
        return
    print(username)
    print("\t{} active sessions", user.getSessionCount())
    user.logout()
    print("user: '{}' was logged out", username)
    print("\t{} active sessions", user.getSessionCount())

def logoutAllUsers():
    from django.contrib.sessions.models import Session
    from django.contrib.auth import logout
    from account.models import User
    from django.http import HttpRequest

    now = datetime.now()
    request = HttpRequest()

    sessions = Session.objects.filter(expire_date__gt=now)
    users = dict(User.objects.values_list('id', 'username'))
    printYellow("LOGGING OUT ALL ACTIVE SESSIONS...")
    printRed('\tFound {} not-expired session(s).'.format(len(sessions)))

    for session in sessions:
        username = session.get_decoded().get('_auth_user_id')
        request.session = init_session(session.session_key)
        logout(request)
        printGreen('\tlogged out {}'.format(username))

def pushit_uploadRelease(project, file_path, version_num=None, host=None, token=None):
    media = open(file_path,'rb')
    files = {'media': media}
    data = {"project":project, "make_current":1}
    if version_num:
        data["version_num"] = version_num
    else:
        data["auto_version"] = 1

    if token:
        data["token"] = token
    r = requests.post(url, files=files, data=data)
    media.close()

def rsync(from_path, to_path, exclude=[]):
    cmd = ["rsync", "-avzh"]
    if "@" in to_path:
        cmd.append('-e "ssh -o ConnectTimeout=2 -o ServerAliveInterval=2 -ServerAliveCountMax=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"')
    for ex in exclude:
        cmd.append("--exclude")
        cmd.append(ex)
    cmd.append("--progress")
    cmd.append(from_path)
    cmd.append(to_path)
    raw_cmd = " ".join(cmd)
    os.system(raw_cmd)

def zipdir(path, output_file):
    import zipfile
    zipf = zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED)
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            zipf.write(os.path.join(root, file))
    zipf.close()


import pkgutil
import importlib

def hasModule(mod):
    if pkgutil.find_loader(mod) is not None:
        return importlib.import_module(mod)
    return None

def testApps(apps=None):
    if not apps:
        initDJANGO()
        apps = settings.INSTALLED_APPS

    printYellow("\nChecking DJANGO apps for errors....")
    for app in apps:
        try:
            path = os.path.join(DJANGO_ROOT, app, "rpc.py")
            path2 = os.path.join(DJANGO_ROOT, app, "rpc")
            if os.path.exists(path) or os.path.exists(path2):
                sys.stdout.write("{0}: ".format(app.rjust(16)))
                module = hasModule(app + '.rpc')
                printGreen("pass")
        except ImportError as err:
            printRed("fail")
            printRed("**** {0} ****".format(err))
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)
        except SyntaxError as serr:
            printRed("fail")
            printRed("Exception in user code:")
            print(('-'*60))
            traceback.print_exc(file=sys.stdout)
            print(('-'*60))
            sys.exit(1)
    printGreen("ALL PASSED".rjust(22))

def logChanges():
    with open(CHANGELOG, "r") as f:
        old = f.read()

    commit = ""
    pos = old.find("## ")
    if pos > 0:
        header = old[pos:]
        print(header[:200])
        header = header[:header.find('\n')].split('|')
        print(header)
        commit = header[2].strip()
    print(commit)
    changes = gitChanges(commit)
    if not len(changes):
        return

    new_commit = changes[0]["commit"]
    print(new_commit)
    if new_commit in old:
        return

    with open(CHANGELOG, "w") as f:
        f.write("\n## {} | {} | {}\n".format(version.VERSION, changes[0].date, changes[0].commit))
        for change in changes:
            f.write(" * {subject} - {name}\n".format(**change))
            if change.body:
                f.write("\n```{body}```".format(**change))
        f.write("\n")
        f.write(old)

    
def gitChanges(commit):
    formatting = """--pretty=format:%H^^%h^^%s^^%b^^%aN^^%aE^^%aD@@@"""
    out = runGit("--no-pager", "log", "{}..HEAD".format(commit), formatting).split("@@@\n")
    logs = []
    for line in out:
        line = line.replace("@@@", "")
        parts = line.split("^^")
        if len(parts) > 3:
            log = UberDict()
            log.commit = parts[0]
            log.abbreviated_commit = parts[1]
            log.subject = parts[2]
            log.body = parts[3]
            log.name = parts[4]
            log.email = parts[5]
            log.date = parts[6]
            if log["subject"].startswith("changelog:") or log["subject"].startswith("Merge branch"):
                continue
            logs.append(log)
    return logs


def bumpVersion(bump_major, bump_minor, bump_rev):
    vfile = VER_FILE
    if not os.path.exists(vfile):
        printRed("!! Could not find version file !!")
        return 0

    if bump_major:
        major = version.major + 1
        minor = 0
        rev = 0
    elif bump_minor:
        major = version.major
        minor = version.minor + 1
        rev = 0
    else:
        major = version.major
        minor = version.minor
        rev = version.rev + 1

    saveVersion(major, minor, rev)

    print("BUMPING Version....")
    print(("\tOLD VERSION: {0}".format(version.VERSION)))
    importlib.reload(version)
    printGreen("\tNEW VERSION: {0}\n".format(version.VERSION))




def getGitBranch():
    branch_file=os.path.join(ROOT, ".git", "HEAD")
    if os.path.exists(branch_file):
        try:
            with open(branch_file, "r") as f:
                line = f.read().strip()
                return line.split('/')[-1]
        except:
            pass
    return None

def runGit(*args):
    cmd = ["git"]
    cmd.extend(list(args))
    try:
        return toString(subprocess.check_output(cmd))
    except:
        pass

def switchBranch(new_branch):
    runGit("checkout", new_branch)

def gitPull():
    runGit("pull")


def mergeFrom(from_branch, to_branch):
    eval(input("merging {} into {}... (any key to continue)".format(from_branch, to_branch)))
    switchBranch(from_branch)
    gitPull()
    switchBranch(to_branch)
    runGit("merge", from_branch)
    runGit("push")
    print("done")

def isMigrationsSynced(database):
    return False if getMigrations(database) else True

def showMigrations():
    os.system("./django/manage.py showmigrations | grep '\[ \]'")

# from django.apps import apps
# from django.db.migrations.executor import MigrationExecutor
# from django.db.migrations.autodetector import MigrationAutodetector
# from django.db.migrations.state import ProjectState
# from django.db import connections, DEFAULT_DB_ALIAS

def getMigrations(database):
    initDJANGO()
    from django.db.migrations.executor import MigrationExecutor
    from django.db import connections
    connection = connections[database]
    connection.prepare_database()
    executor = MigrationExecutor(connection)
    targets = executor.loader.graph.leaf_nodes()
    return executor.migration_plan(targets)

def checkMissing(database):
    initDJANGO()
    from django.apps import apps
    from django.db.migrations.executor import MigrationExecutor
    from django.db.migrations.autodetector import MigrationAutodetector
    from django.db import connections, DEFAULT_DB_ALIAS
    from django.db.migrations.state import ProjectState
    changed = set()
    connection = connections[database]
    try:
        executor = MigrationExecutor(connection)
    except Exception:
        sys.exit("Unable to check migrations: "
                 "cannot connect to database\n")
    autodetector = MigrationAutodetector(
        executor.loader.project_state(),
        ProjectState.from_apps(apps),
    )
    return autodetector.changes(graph=executor.loader.graph)

def makeMigration(app_label):
    if os.system("./django/manage.py makemigrations {}".format(app_label)) == 0:
        os.system("git add django/{}/migrations".format(app_label))
        os.system("./django/manage.py migrate {}".format(app_label))

def printColor(color, msg):
    print(("{}{}{}".format(color, msg, ConsoleColors.OFF)))

def printGreen(msg):
    printColor(ConsoleColors.GREEN, msg)

def printRed(msg):
    printColor(ConsoleColors.RED, msg)

def printYellow(msg):
    printColor(ConsoleColors.YELLOW, msg)

def printBlue(msg):
    printColor(ConsoleColors.BLUE, msg)

def printBanner():
    print(("=" * 80))
    printYellow("{} - {} - {}".format(PROJECT_NAME, version.VERSION, getGitBranch()))
    print(("=" * 80))

class ConsoleColors:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    PINK = "\033[35m"
    BLUE = '\033[34m'
    WHITE = '\033[37m'

    HBLACK = '\033[90m'
    HRED = '\033[91m'
    HGREEN = '\033[92m'
    HYELLOW = '\033[93m'
    HBLUE = '\033[94m'
    HPINK = "\033[95m"
    HWHITE = '\033[97m'

    HEADER = '\033[95m'
    FAIL = '\033[91m'
    OFF = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def toString(value):
    if isinstance(value, bytes):
        value = value.decode()
    elif isinstance(value, bytearray):
        value = value.decode("utf-8")
    elif isinstance(value, (int, float)):
        value = str(value)
    return value


if __name__ == '__main__':
    print((version.VERSION))
