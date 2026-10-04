#!/bin/sh
# restart-mailboxes.sh — restart every rmail mailbox on this machine, so
# each one runs the program as it is now rather than as it was when it
# started
#
# One program folder serves every mailbox on a machine (#102), so
# updating that folder is the whole update.  But a running mailbox keeps
# the program it loaded when it started; until its service is restarted
# it goes on running the old code, and nothing says so.  This script
# restarts each mailbox's service from a list kept at the top of this
# file, then checks that each one is running again.
#
# This file, scripts/restart-mailboxes.sh, is built for one machine from
# the template at scripts/.templates/restart-mailboxes.sh, by
# scripts/make-restart-script.sh (the installer runs that the first time;
# rebuilding with --force keeps the list).  It is not tracked by git, so
# the list below belongs to this machine and survives every update.  The
# template holds a restart method for each kind of service manager; this
# copy keeps only the one this machine uses.  (#622)
#
# Usage:
#   ./restart-mailboxes.sh                  restart every service in the list
#   ./restart-mailboxes.sh NAME...          restart only these, this once;
#                                           the list is not changed
#   ./restart-mailboxes.sh --add NAME       add NAME to the list (if it is not
#                                           there already); restart nothing
#   ./restart-mailboxes.sh --check          say whether every listed service
#                                           is installed; restart nothing
#   ./restart-mailboxes.sh --dir=PATH ...   the program folder, if this copy
#                                           was moved from where it was built
#
# With an empty list and no names given, it asks for the names and writes
# them into the list below.  The installer adds each mailbox it sets up.
#
# Exit status: 0 every service restarted and running (or, with --add, the
# name is listed; with --check, every listed service is installed);
# 1 otherwise.

# The program folder this copy was built for, and the services to restart
# in it: each mailbox's service name, separated by spaces.
DIR="@PROGRAM_DIR@"
MAILBOX_SERVICES=""

# The service manager this copy was built for (runit, systemd, openrc or
# nixos).  Only that manager's block is below.
SERVICE_MANAGER="@SERVICE_MANAGER@"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
err()  { printf "  \033[31merror\033[0m %s\n" "$*" >&2; }
info() { printf "       %s\n" "$*"; }

# {{{ as_root
# Most service managers only let root restart a service.  Already root:
# run the command as it is.  Otherwise: through sudo, which asks for the
# password once and remembers it for the rest of the run.  No sudo at
# all: stop, saying what is needed, rather than carrying on and failing
# one service at a time.
as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        err "restarting needs root, and sudo is not installed"
        info "run this script as root instead"
        exit 1
    fi
}
# }}}

# Each manager's block defines the same three operations, so the shared
# part below never asks which manager it is talking to:
#   service_is_installed NAME   true if this manager has a service NAME
#   restart_service NAME        restart it
#   service_is_running NAME     true if it is running now

# {{{ manager: runit
# runit keeps each enabled service as a folder in /var/service (or
# wherever SVDIR says).  sv is given the full folder path, because sudo
# clears SVDIR from the environment it passes on.
SVDIR="${SVDIR:-/var/service}"

# {{{ service_is_installed
service_is_installed() {
    [ -d "$SVDIR/$1" ]
}
# }}}

# {{{ restart_service
restart_service() {
    as_root sv restart "$SVDIR/$1"
}
# }}}

# {{{ service_is_running
# sv status prints "run: <path>: (pid N) Ns" for a running service, and
# "down:", "finish:" or "warning:" otherwise.
service_is_running() {
    as_root sv status "$SVDIR/$1" | grep -q '^run:'
}
# }}}
# }}} manager: runit

# {{{ manager: systemd
# A mailbox's service on systemd is either a user service (the installer's
# no-root choice) or a system one.  Which one is looked up per name, and
# the operation is picked from a table by that answer: the user kind needs
# no root, the system kind does.

# {{{ service_scope
# Prints "user" or "system" for the kind of service NAME is, or "none"
# when systemd knows neither.
service_scope() {
    if systemctl --user cat "$1.service" >/dev/null 2>&1; then
        echo user
    elif systemctl cat "$1.service" >/dev/null 2>&1; then
        echo system
    else
        echo none
    fi
}
# }}}

# {{{ restart_user / restart_system
restart_user()   { systemctl --user restart "$1.service"; }
restart_system() { as_root systemctl restart "$1.service"; }
# }}}

# {{{ running_user / running_system
running_user()   { systemctl --user is-active --quiet "$1.service"; }
running_system() { systemctl is-active --quiet "$1.service"; }
# }}}

# {{{ service_is_installed
service_is_installed() {
    [ "$(service_scope "$1")" != none ]
}
# }}}

# {{{ restart_service
restart_service() {
    "restart_$(service_scope "$1")" "$1"
}
# }}}

# {{{ service_is_running
service_is_running() {
    "running_$(service_scope "$1")" "$1"
}
# }}}
# }}} manager: systemd

# {{{ manager: openrc
# OpenRC keeps each service as a script in /etc/init.d (or wherever INITD
# says; the tests point it at a scratch folder).  rc-service status exits
# 0 only for a started service.
INITD="${INITD:-/etc/init.d}"

# {{{ service_is_installed
service_is_installed() {
    [ -f "$INITD/$1" ]
}
# }}}

# {{{ restart_service
restart_service() {
    as_root rc-service "$1" restart
}
# }}}

# {{{ service_is_running
service_is_running() {
    as_root rc-service "$1" status >/dev/null
}
# }}}
# }}} manager: openrc

# {{{ manager: nixos
# NixOS runs its services under systemd, as system services declared in
# the system configuration (the installer writes one .nix file per
# mailbox).  Restarting one needs no rebuild: the configuration is
# unchanged, only the program it points at is new.

# {{{ service_is_installed
service_is_installed() {
    systemctl cat "$1.service" >/dev/null 2>&1
}
# }}}

# {{{ restart_service
restart_service() {
    as_root systemctl restart "$1.service"
}
# }}}

# {{{ service_is_running
service_is_running() {
    systemctl is-active --quiet "$1.service"
}
# }}}
# }}} manager: nixos

# {{{ is_service_name
# A service name is letters, digits and . _ @ -.  Anything else is
# refused, because the name is written into this file's list line and
# handed to the service manager, and neither should see a space, a quote
# or a slash.
is_service_name() {
    case "$1" in
        ''|*[!A-Za-z0-9._@-]*) return 1 ;;
        *) return 0 ;;
    esac
}
# }}}

# {{{ ask_for_names
# Reads one service name per line until a blank one, and prints them
# space-separated.  The prompts go to the terminal (standard error), so
# only the names come back to the caller.
ask_for_names() {
    _names=""
    {
        echo ""
        echo "  No mailboxes are listed in this script yet."
        echo "  Type the service name of each mailbox, pressing enter after"
        echo "  each one.  When you're done, give a blank name (press enter"
        echo "  twice)."
        echo ""
    } >&2
    while :; do
        printf "  service name: " >&2
        # end of input counts as done, the same as a blank name
        IFS= read -r _name || break
        # a blank name: the list is finished
        [ -z "$_name" ] && break
        if is_service_name "$_name"; then
            _names="${_names:+$_names }$_name"
        else
            # refused, and asked again; nothing is added
            err "not a service name: '$_name' (letters, digits, . _ @ - only)"
        fi
    done
    echo "$_names"
}
# }}}

# {{{ write_list
# Rewrites this file's list line with NAMES.  The new file is written
# beside this one and moved over it, rather than edited in place: the
# shell is still reading this file as it runs, and a file replaced by a
# move keeps the old one open for the reader, where one rewritten in
# place would shift the text under it.
write_list() {
    _self="$DIR/scripts/restart-mailboxes.sh"
    _count=$(grep -c '^MAILBOX_SERVICES=' "$_self")
    if [ "$_count" != 1 ]; then
        err "$_self has $_count list lines (MAILBOX_SERVICES=...), expected exactly 1"
        info "the names were not saved; add them to that line by hand"
        return 1
    fi
    sed "s/^MAILBOX_SERVICES=.*/MAILBOX_SERVICES=\"$1\"/" "$_self" > "$_self.new" &&
        chmod 755 "$_self.new" &&
        mv "$_self.new" "$_self"
}
# }}}

# {{{ main
main() {
    _given=""
    _mode=restart
    _add=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --dir=*)
                DIR="${1#--dir=}" ;;
            --add)
                # the next argument is the name to add
                _mode=add
                _add="${2:-}"
                [ $# -gt 0 ] && shift ;;
            --check)
                _mode=check ;;
            -h|--help)
                # the header comment, up to its first blank line
                sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
                exit 0 ;;
            -*)
                err "unknown option: $1"
                exit 1 ;;
            *)
                if ! is_service_name "$1"; then
                    err "not a service name: '$1' (letters, digits, . _ @ - only)"
                    exit 1
                fi
                _given="${_given:+$_given }$1" ;;
        esac
        shift
    done

    # --add: put one name on the list, unless it is there already, and
    # restart nothing.  The installer does this for each mailbox it sets
    # up, so a machine set up by the installer never has an empty list.
    if [ "$_mode" = add ]; then
        if ! is_service_name "$_add"; then
            err "--add needs a service name (letters, digits, . _ @ - only), got '$_add'"
            exit 1
        fi
        case " $MAILBOX_SERVICES " in
            *" $_add "*)
                ok "$_add is already listed in $DIR/scripts/restart-mailboxes.sh"
                exit 0 ;;
        esac
        if write_list "${MAILBOX_SERVICES:+$MAILBOX_SERVICES }$_add"; then
            ok "added $_add to the list in $DIR/scripts/restart-mailboxes.sh"
            exit 0
        fi
        exit 1
    fi

    # --check: say whether every name (given, or else listed) is an
    # installed service, and restart nothing.  The installer asks this
    # before offering a restart, because a service it has just written
    # may still be waiting for the owner to install it.
    if [ "$_mode" = check ]; then
        _services="${_given:-$MAILBOX_SERVICES}"
        if [ -z "$_services" ]; then
            err "the list in $DIR/scripts/restart-mailboxes.sh is empty"
            exit 1
        fi
        _missing=""
        for _svc in $_services; do
            service_is_installed "$_svc" || _missing="${_missing:+$_missing }$_svc"
        done
        if [ -n "$_missing" ]; then
            err "no $SERVICE_MANAGER service named: $_missing"
            exit 1
        fi
        ok "every listed mailbox is an installed $SERVICE_MANAGER service: $_services"
        exit 0
    fi

    # Which names to restart.  Names on the command line: those, this
    # once.  Otherwise the list.  An empty list: ask, when there is
    # someone to ask, and keep the answers; with no one to ask, stop.
    if [ -n "$_given" ]; then
        _services="$_given"
    elif [ -n "$MAILBOX_SERVICES" ]; then
        _services="$MAILBOX_SERVICES"
    elif [ -t 0 ]; then
        _services=$(ask_for_names)
        if [ -z "$_services" ]; then
            err "no names given; nothing to restart"
            exit 1
        fi
        if write_list "$_services"; then
            ok "saved the list: $_services"
        else
            exit 1
        fi
    else
        err "the list in $DIR/scripts/restart-mailboxes.sh is empty, and there is no terminal to ask on"
        info "give the service names as arguments, or run this once by hand to fill the list"
        exit 1
    fi

    echo ""
    echo "rmail: restarting mailboxes ($SERVICE_MANAGER)"
    echo ""

    # Every name is checked before any is restarted, so a mistyped name
    # cannot leave half the machine on the new program and half on the
    # old.
    _missing=""
    for _svc in $_services; do
        service_is_installed "$_svc" || _missing="${_missing:+$_missing }$_svc"
    done
    if [ -n "$_missing" ]; then
        err "no $SERVICE_MANAGER service named: $_missing"
        info "nothing was restarted"
        exit 1
    fi

    _failed=0
    for _svc in $_services; do
        if restart_service "$_svc" >/dev/null; then
            ok "restarted $_svc"
        else
            err "could not restart $_svc"
            _failed=$((_failed + 1))
        fi
    done

    # A daemon that dies on startup (a broken update, a port taken)
    # usually does so within its first second or two, so the check waits
    # a moment rather than asking the instant the restart returns.  The
    # wait can be shortened (RMAIL_RESTART_SETTLE=0) for the tests, whose
    # stand-in services have nothing to start.
    sleep "${RMAIL_RESTART_SETTLE:-3}"
    echo ""
    for _svc in $_services; do
        if service_is_running "$_svc"; then
            ok "$_svc is running"
        else
            err "$_svc is not running"
            _failed=$((_failed + 1))
        fi
    done

    echo ""
    if [ "$_failed" -eq 0 ]; then
        printf "  \033[32mevery mailbox restarted\033[0m\n"
        exit 0
    fi
    printf "  \033[31m%d problem(s)\033[0m\n" "$_failed"
    exit 1
}
# }}}

main "$@"
