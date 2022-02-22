#!/usr/bin/env python3.8

from script_helper import *
from optparse import OptionParser

def main():
    branch = getGitBranch()
    if branch == "develop":
        print("this is the bottom, no where to pull from")
    elif branch == "beta":
        mergeFrom("develop", branch)
    elif branch == "master":
        mergeFrom("beta", branch)

if __name__ == '__main__':
    main()