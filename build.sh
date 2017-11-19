#!/bin/bash
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig

./configure \
    --disable-werror \
    --prefix=$PWD/openocd-gct301s-release \
    --program-suffix=-gct301s 

read -p "Press any key to continue... " -n1 -s
make
make install
tar czvf openocd-gct301s-release_0.10.0.tar.gz openocd-gct301s-release
rm -rf openocd-gct301s-release
