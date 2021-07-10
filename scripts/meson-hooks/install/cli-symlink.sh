#!/bin/sh

bindir=

case $1 in
  /*) bindir=$(sed -E 's/(.*?)\$MESON_INSTALL_PREFIX/\1/' <<< $MESON_INSTALL_DESTDIR_PREFIX)/$1 ;;
  *) bindir=$MESON_INSTALL_DESTDIR_PREFIX/$1 ;;
esac

ln --symbolic --force "$2" "$bindir/$3"
