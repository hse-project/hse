# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

import shlex
from typing import List


def shlex_join(arglist: List[str]) -> str:
    #
    # Implementation for Python 3.7 and older
    # https://bugs.python.org/issue22454
    #
    return " ".join([shlex.quote(x) for x in arglist])
