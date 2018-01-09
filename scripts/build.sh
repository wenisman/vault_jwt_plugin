#!/bin/sh

set -ex

echo hello

#go get -v

#GOARCH="$2"
#GOOS="$1"

#if [ -z "$GOOS" ] 
#then
#  GOOS="linux"
#fi

#if [ -z "$GOARCH" ] 
#then
#  GOARCH="386"
#fi

#CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-s" -a -installsuffix cgo -o build/jwtplugin
#shasum -a 256 -p build/jwtplugin | cut -d ' ' -f 1 > "build/jwtplugin.sha1"

docker build -t $1 .