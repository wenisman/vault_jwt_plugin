#! /bin/sh
set -ex

NAME=$1
vault unmount $NAME

vault delete /sys/plugins/catalog/$NAME

vault write sys/plugins/catalog/$NAME sha_256=$(cat "${NAME}".sha1) command=$NAME

#vault mount -path=$NAME -plugin-name=$NAME plugin
vault auth-disable $NAME
vault auth-enable -path=$NAME -plugin-name=$NAME plugin