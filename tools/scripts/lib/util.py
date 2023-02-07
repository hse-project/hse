# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

import lzma
import yaml


class Util:
    def __init__(self):
        pass

    def humanize(self, number):
        n = number
        for sfx in ["", "K", "M", "G", "T", "P", "E"]:
            if abs(n) < 1000:
                return "{:.2f}{}".format(n, sfx)
            n = n / 1000

        return "{:.2f}{}".format(n, sfx)

    def file_to_yaml(self, filepath):
        if filepath.endswith(".xz"):
            fd = lzma.open(filepath, "r")
        else:
            fd = open(filepath, "r")

        try:
            shape = fd.read()
        finally:
            fd.close()

        return yaml.safe_load(shape)
