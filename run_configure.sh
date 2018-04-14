#!/bin/bash

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig

#./configure --disable-werror --prefix=/opt/openocd
./configure --disable-werror --prefix=$PWD/build

