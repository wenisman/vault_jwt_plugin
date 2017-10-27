
#! /bin/sh
set -ex

go get

go build -o build/jwtplugin
shasum -a 1 -p build/jwtplugin | cut -d ' ' -f 1 > "build/jwtplugin.sha1"