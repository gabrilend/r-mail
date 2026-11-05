#!/bin/sh
# view.sh — read a mailbox in the terminal (#711); see clients/shared/rmail-view.lua
DIR="$(cd "$(dirname "$0")" && pwd)"
exec lua "$DIR/../shared/rmail-view.lua" "$@"
