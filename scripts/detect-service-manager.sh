#!/bin/sh
# detect-service-manager.sh — say which program starts and stops services on
# this machine: nixos, systemd, runit, openrc, or unknown
#
# rmail runs each mailbox as a service, and every service manager wants its
# service written differently and restarted with a different command.  The
# installer, the docs builder and the restart script all need the same
# answer, so it is worked out here, once, and printed as one word.  (#614)
#
# How it decides, first match wins:
#   nixos    /etc/NIXOS exists.  NixOS runs systemd, but rewrites systemd's
#            files on every rebuild, so a service is declared another way.
#   process 1's name   the program the kernel started first is the service
#            manager: systemd, runit, or openrc-init.
#   a manager's command on the path   systemctl, then sv, then rc-service,
#            for a machine where process 1's name says nothing useful (a
#            container, say).
#   unknown  none of these.
#
# Usage:
#   scripts/detect-service-manager.sh      prints the word, exit status 0
#
# Takes no folder argument: it asks the machine, not the checkout.

# {{{ detect
detect() {
    if [ -f /etc/NIXOS ]; then
        echo nixos
        return
    fi
    if [ -f /proc/1/comm ]; then
        case "$(cat /proc/1/comm)" in
            systemd)     echo systemd; return ;;
            runit)       echo runit;   return ;;
            openrc-init) echo openrc;  return ;;
        esac
    fi
    # process 1 named something else: ask which commands exist
    if   command -v systemctl  >/dev/null 2>&1; then echo systemd
    elif command -v sv         >/dev/null 2>&1; then echo runit
    elif command -v rc-service >/dev/null 2>&1; then echo openrc
    else echo unknown
    fi
}
# }}}

detect
