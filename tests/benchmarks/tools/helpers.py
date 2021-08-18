# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

import shlex
from typing import List


def shlex_join(arglist: List[str]) -> str:
    #
    # Implementation for Python 3.7 and older
    # https://bugs.python.org/issue22454
    #
    return " ".join([shlex.quote(x) for x in arglist])
