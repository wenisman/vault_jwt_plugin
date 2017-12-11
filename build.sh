
#! /bin/sh
set -ex

go get -v

CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/jwtplugin
shasum -a 256 -p build/jwtplugin | cut -d ' ' -f 1 > "build/jwtplugin.sha1"