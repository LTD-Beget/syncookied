#!/bin/sh
set -ex

TARGET=`arch`-unknown-linux-musl
BUILD_DIR=$(pwd)
export PATH=$PATH:$HOME/.cargo/bin/

echo "=> Installing rust"
# uninstall the rust toolchain installed by travis, we are going to use rustup
sh ~/rust/lib/rustlib/uninstall.sh

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=$TRAVIS_RUST_VERSION

rustc -V
cargo -V

rustup target add $TARGET

echo "=> Cloning netmap"
git clone -q --depth=1 https://github.com/luigirizzo/netmap/

echo "=> Cloning libpcap"
git clone -q --depth=1 https://github.com/the-tcpdump-group/libpcap

echo "=> Cloning linux headers"
git clone -q --depth=1 https://github.com/sabotage-linux/kernel-headers

echo "=> Installing headers locally"
(cd kernel-headers && make ARCH=`arch` prefix=/ DESTDIR=`pwd`/kernel-headers install > /dev/null)

echo "=> Building static libpcap"
cd libpcap && CC=musl-gcc CFLAGS='-fPIC -I../kernel-headers/kernel-headers/include' ./configure
make

STATIC_LIBPCAP_PATH=$(pwd) CFLAGS=-I${BUILD_DIR}/netmap/sys cargo build --verbose --target=$TARGET --release
