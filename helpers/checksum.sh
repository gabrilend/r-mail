#!/bin/sh
# checksum.sh — SHA-256 hash of a file
# Usage: helpers/checksum.sh /path/to/file
# Output: hex digest string
sha256sum "$1" | sed 's/ .*//'
