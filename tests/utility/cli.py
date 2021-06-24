import argparse
import pathlib
import sys

__parser = argparse.ArgumentParser()
__parser.add_argument("-C", "--home", type=pathlib.Path, default=pathlib.Path.cwd())

__ns = __parser.parse_args(sys.argv[1:])

HOME: pathlib.Path = __ns.home
