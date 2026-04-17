#!/bin/sh
# run.sh — launch the rmail thin client on Linux
DIR="$(cd "$(dirname "$0")" && pwd)"
exec lua "$DIR/../shared/rmail-client.lua" "$@"
