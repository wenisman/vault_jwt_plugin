#! /bin/sh

go get -v
get test -v ./lib/*
CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo .