#!/bin/sh
# view-logs.sh — display rmail daemon logs in real-time
#
# Usage: ./scripts/view-logs.sh [log-file | service-name]
#
# Logs live in RAM-backed /tmp, one file per service, named after the
# service: a mailbox at /home/ritz/mail is served by rmail-home-ritz-mail
# and logs to /tmp/rmail-home-ritz-mail.log.  install.sh's five init
# branches all write service files that redirect there.
#
# With no argument and exactly one log present, that one is followed.
# With several, they are listed and one is chosen — the alternative,
# following all of them at once, produces interleaved lines with nothing
# saying which daemon wrote which, which is the problem that having one
# log per service exists to solve.  (Re #377.)
#
# A log named simply /tmp/rmail.log is from before services were named per
# mailbox.  It is still listed, because a daemon installed then is still
# running now.
#
# If no log file exists, fall back to `journalctl -u <service> -f` when
# systemd is active — that covers NixOS installs whose configuration.nix
# defines a service logging to journald instead of to a file.  See the
# 2026-04-17 follow-up in issues/completed/205-redirect-service-logs-to-tmp.md.

# {{{ follow()
follow() {
    echo "Following $1  (Ctrl-C to stop)"
    echo ""
    # -F follows across rotations and service restarts, unlike -f.
    exec tail -F "$1"
}
# }}}

# {{{ list_logs()
# Every rmail log in /tmp, newest first.  Newest first because the one you
# just installed is the one you almost certainly want to look at, so the
# ordering means the common case needs no thought.
list_logs() {
    find /tmp -maxdepth 1 -name 'rmail*.log' -type f -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr | cut -d' ' -f2-
}
# }}}

# {{{ service_of()
# Turns /tmp/rmail-home-ritz-mail.log back into rmail-home-ritz-mail, which
# is what journalctl and systemctl want to be told.
service_of() {
    _base=${1##*/}
    printf '%s' "${_base%.log}"
}
# }}}

# An argument is either a path to follow or the name of a service whose log
# to follow.  Accepting both means the name printed by the installer can be
# pasted here directly, without the reader having to know where logs live.
if [ -n "$1" ]; then
    if [ -f "$1" ]; then
        follow "$1"
    elif [ -f "/tmp/$1.log" ]; then
        follow "/tmp/$1.log"
    else
        echo "No log at '$1' and none for a service by that name."
        echo ""
        LOGS=$(list_logs)
        if [ -n "$LOGS" ]; then
            echo "These exist:"
            printf '%s\n' "$LOGS" | sed 's|^|    |'
        fi
        exit 1
    fi
fi

LOGS=$(list_logs)
COUNT=$(printf '%s\n' "$LOGS" | grep -c . || true)

# Exactly one log is the ordinary case on a machine with one mailbox, and it
# should not turn into a menu with one entry.
if [ "$COUNT" = "1" ]; then
    follow "$LOGS"
fi

if [ "$COUNT" -gt 1 ]; then
    echo "Several rmail services are logging on this machine:"
    echo ""
    i=1
    printf '%s\n' "$LOGS" | while IFS= read -r f; do
        [ -n "$f" ] || continue
        printf '  %d) %-40s %s\n' "$i" "$(service_of "$f")" "$(date -r "$f" '+last written %H:%M:%S')"
        i=$((i + 1))
    done
    echo ""
    printf 'Which one? [1] '
    read -r choice
    [ -z "$choice" ] && choice=1
    chosen=$(printf '%s\n' "$LOGS" | sed -n "${choice}p")
    if [ -z "$chosen" ]; then
        echo "No such choice: $choice"
        exit 1
    fi
    follow "$chosen"
fi

# No log files at all.  If a service is running under systemd with journald
# as its sink, that is the right place to look instead.
if command -v systemctl >/dev/null 2>&1; then
    for scope in "--user" ""; do
        # shellcheck disable=SC2086
        running=$(systemctl $scope list-units --type=service --state=running \
                  --no-legend 'rmail*' 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$running" ]; then
            echo "$running is running but has written no log file."
            echo "Following journald output instead.  Ctrl-C to stop."
            echo ""
            # shellcheck disable=SC2086
            exec journalctl $scope -u "$running" -f
        fi
    done
fi

# Neither a log file nor a running service.  Keep the original
# wait-for-file behaviour so a slow-starting runit or openrc install still
# works: start the service, run this, see output as soon as it appears.
echo "No rmail logs found in /tmp, and no rmail service appears to be running."
echo ""
echo "Waiting for a log file to appear..."
while true; do
    LOGS=$(list_logs)
    if [ -n "$LOGS" ]; then
        break
    fi
    sleep 1
done
echo "Log file created."
follow "$(printf '%s\n' "$LOGS" | head -1)"
