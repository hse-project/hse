#!/usr/bin/env python3

import os
import sys
import re
import argparse
import string

CMD = os.path.basename(__file__)

def err_msg(*lines, **kwargs):
    print(*lines,
          sep=kwargs.get('sep','\n'),
          file=kwargs.get('file',sys.stderr))

def quit(*lines, **kwargs):
    err_msg(*lines, **kwargs)
    sys.exit(-1)

def exception_msg():
    return str(sys.exc_info()[1])

def parse_command_line(args):
    parser = argparse.ArgumentParser(
        prog=CMD,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
        description="Walk source tree and show '#include' dependencies.")

    parser.add_argument(
        "--list-dirs",
        dest="list_dirs",
        action='store_true',
        required=False,
        help="show list of directories that have source files")

    parser.add_argument(
        "--list-src",
        dest="list_src",
        action='store_true',
        required=False,
        help="show list of source files")

    parser.add_argument(
        "dirs",
        nargs='*',
        help="directories to search")

    return parser.parse_args(args)

options = parse_command_line(sys.argv[1:])

optdict = vars(options)
if (not 'dirs' in optdict) or len(optdict['dirs']) == 0:
    optdict['dirs'] = ['.']

filename_regex = re.compile(r'^.*\.(c|h|cpp|hpp)$')
include_directive_regex = re.compile(r'^\s*#\s*include\s*["<](.*?)[">]')
mse_include_regex = re.compile('^mse_|/mse_')


for top_dir in optdict['dirs']:

    for root, dirs, files in os.walk(top_dir):

        try:
            # dirs that should not be followed
            dirs.remove('.git')
        except:
            pass

        included_files = dict()

        for f in files:
            m = filename_regex.match(f)
            if m:

                fullpath = root+'/'+f

                if optdict['list_dirs']:
                    print(root)
                    break

                if optdict['list_src']:
                    print(fullpath)
                    break

                for line in open(fullpath,'r'):
                    m = include_directive_regex.match(line)
                    if m:
                        included_files.setdefault(m.group(1),True)

        mse_files = []
        sys_files = []
        incfiles = sorted(included_files.keys())
        if len(incfiles) > 0:
            for f in incfiles:
                m = mse_include_regex.match(f)
                if m:
                    mse_files.append(f)
                else:      
                    sys_files.append(f)

            print('#')
            for f in mse_files:
                print('%s:  MSE  %s'%(root, f))
            for f in sys_files:
                print('%s:  SYS  %s'%(root, f))
