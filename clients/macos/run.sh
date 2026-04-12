#!/bin/sh
# run.sh — launch the rmail thin client on macOS
DIR="$(cd "$(dirname "$0")" && pwd)"
exec lua "$DIR/../shared/rmail-client.lua" "$@"
