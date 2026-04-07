#!/bin/sh
# filename.sh — extract the filename from a path
# Usage: scripts/filename.sh /home/ritz/mail/inbox/hello-world
# Output: hello-world
basename "$1"
