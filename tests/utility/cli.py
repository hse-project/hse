import argparse
import pathlib

__parser = argparse.ArgumentParser()
__parser.add_argument("-C", "--home", type=pathlib.Path, default=pathlib.Path.cwd())

__ns = __parser.parse_args()

HOME: pathlib.Path = __ns.home
