#!/bin/sh
# filename.sh — extract the filename from a path
# Usage: helpers/filename.sh /home/ritz/mail/inbox/hello-world
# Output: hello-world
echo "$1" | sed 's|.*/||'
