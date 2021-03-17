import shlex

from base import BaseTest


class CommandTest(BaseTest):
    def __init__(self, name, cmdline):
        super().__init__(name)
        self.cmdline = cmdline

        self.report["command"] = {"cmdline": cmdline}
        self.report["tool"] = "command"

    def execute(self):
        args = shlex.split(self.cmdline)

        super()._run_command(args)
