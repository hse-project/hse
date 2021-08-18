#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

bindir=

case $1 in
  /*) bindir=$(sed -E 's/(.*?)\$MESON_INSTALL_PREFIX/\1/' <<< $MESON_INSTALL_DESTDIR_PREFIX)/$1 ;;
  *) bindir=$MESON_INSTALL_DESTDIR_PREFIX/$1 ;;
esac

ln --symbolic --force "$2" "$bindir/$3"
