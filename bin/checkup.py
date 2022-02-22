#!/usr/bin/env python3.8

from script_helper import *
from optparse import OptionParser


parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False )
parser.add_option("-l", "--list", action="store_true", dest="list", default=False, help="force the test to run now" )
parser.add_option("-a", "--app", type="str", dest="app", default=None, help="run only this app/module" )

def main(opts, args):
        printBanner()
        if opts.app:
            testApps([opts.app])
        else:
            testApps()

if __name__ == '__main__':
        main(*parser.parse_args())
