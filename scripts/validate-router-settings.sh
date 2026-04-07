#!/bin/sh
# validate-router-settings.sh — verify port, router settings, and contact reachability
#
# Run this after opening your firewall port. The hairpin NAT test requires
# the port to be open in your firewall; if it isn't, the result will be
# misleading (timeout looks the same as no hairpin NAT support).
#
# Usage: scripts/check-connectivity.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG="${HOME}/.config/rmail/config"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
warn() { printf "  \033[33m!!\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

echo ""
echo "rmail connectivity check"
echo "========================"
echo ""

# --- Read config ---
if [ ! -f "$CONFIG" ]; then
    fail "Config not found at $CONFIG"
    info "Run scripts/install.sh first."
    exit 1
fi

read_config() { grep "^${1}[[:space:]]*=" "$CONFIG" 2>/dev/null \
    | sed 's/^[^=]*=[[:space:]]*//' | head -1 | tr -d '[:space:]'; }

PORT=$(read_config port)
if [ -z "$PORT" ]; then
    fail "Could not read port from $CONFIG"
    exit 1
fi

MAIL_DIR=$(read_config mail | sed "s|^~|$HOME|")
CONTACTS_FILE="${MAIL_DIR}/contacts"

# --- Fetch public IP ---
printf "  Fetching public IP...   "
PUBLIC_IP=""
for service in ifconfig.me icanhazip.com api.ipify.org checkip.amazonaws.com; do
    ip=$(curl -s --max-time 4 "https://$service" 2>/dev/null | tr -d '[:space:]')
    if echo "$ip" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        PUBLIC_IP="$ip"
        break
    fi
done
if [ -z "$PUBLIC_IP" ]; then
    fail "Could not determine public IP — check internet connection"
    echo ""
    exit 1
fi
echo "$PUBLIC_IP"
printf "  Port:                   %s\n" "$PORT"
echo ""

# --- Local port check ---
LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ip -4 addr show 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*scope global.*/\1/p' | head -1)
fi
if [ -n "$LOCAL_IP" ]; then
    printf "  Local IP:               %s\n" "$LOCAL_IP"
    printf "  Checking local port...  "
    curl -s --max-time 2 "http://$LOCAL_IP:$PORT/" >/dev/null 2>&1
    LOCAL_EXIT=$?
    if [ "$LOCAL_EXIT" -eq 28 ]; then
        fail "timed out"
        info "Port $PORT is not reachable on $LOCAL_IP."
        info "Is the port open in your firewall? Is the daemon running?"
    elif [ "$LOCAL_EXIT" -eq 7 ]; then
        warn "connection refused"
        info "Port $PORT on $LOCAL_IP refused the connection."
        info "Is the rmail daemon running?"
    else
        ok "port $PORT is open on $LOCAL_IP"
    fi
    echo ""
else
    info "Could not determine local IP — skipping local port check."
    echo ""
fi

# --- IPv6 check ---
IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep -v "temporary\|deprecated" | sed -n 's/.*inet6 \([0-9a-f:]*\)\/.*/\1/p' | head -1)
if [ -n "$IPV6_ADDR" ]; then
    printf "  IPv6 address:           %s\n" "$IPV6_ADDR"
    printf "  Checking IPv6 port...   "
    curl -s -g --max-time 2 "http://[$IPV6_ADDR]:$PORT/" >/dev/null 2>&1
    IPV6_EXIT=$?
    if [ "$IPV6_EXIT" -eq 28 ]; then
        warn "timed out"
        info "Port $PORT is not reachable on IPv6."
        info "Open the port in your firewall for IPv6 too."
    elif [ "$IPV6_EXIT" -eq 7 ]; then
        warn "connection refused"
        info "Daemon may not be binding IPv6. Check if socket.tcp6 is available."
    else
        ok "port $PORT is open on IPv6"
        info "Contacts can use your IPv6 address — no port forwarding needed!"
    fi
    echo ""
else
    info "No global IPv6 address — IPv6 not available on this network."
    echo ""
fi

# --- Hairpin NAT test ---
# rmail uses AES-256-GCM encryption, so a plain curl will get a garbled
# response — but that still means the TCP connection reached the machine.
# Only curl exit code 28 (timeout) means the packet was dropped by the router.
printf "  Testing hairpin NAT...  "
curl -s --max-time 2 "http://$PUBLIC_IP:$PORT/" >/dev/null 2>&1
CURL_EXIT=$?
if [ "$CURL_EXIT" -eq 28 ]; then
    warn "not supported"
    info "Contacts on your local network cannot reach you via your public IP."
    info "They should use your local IP address instead (e.g. 192.168.x.x):"
    info ""
    info "  you_home.ip    = 192.168.x.x   <- find with: ip addr show"
    info "  you_home.port  = $PORT"
    info "  you_home.token = \"shared-secret\""
    info ""
    info "See docs/ports-explained.md for details."
else
    ok "supported"
fi
echo ""

# --- UPnP test ---
UPNPC=""
if [ -x "$ROOT/deps/bin/upnpc" ]; then
    UPNPC="$ROOT/deps/bin/upnpc"
elif command -v upnpc >/dev/null 2>&1; then
    UPNPC="upnpc"
fi

if [ -z "$UPNPC" ]; then
    info "upnpc not available — skipping UPnP check"
    info "(Run scripts/install.sh to compile it.)"
else
    printf "  Testing UPnP...         "
    UPNPC_OUT=$(timeout 5 "$UPNPC" -s 2>&1)
    if echo "$UPNPC_OUT" | grep -q "Found valid IGD"; then
        warn "UPnP is enabled on your router"
        info "UPnP lets any device on your local network open ports on your"
        info "router without authentication. Malware commonly exploits this."
        info "Consider disabling UPnP in your router's admin panel."
        info "See docs/nat-traversal-report.md for details."
    else
        ok "UPnP not detected"
    fi
fi
echo ""

# --- Per-contact connectivity ---
if [ ! -f "$CONTACTS_FILE" ]; then
    info "Contacts file not found at $CONTACTS_FILE — skipping contact checks."
    echo ""
    exit 0
fi

# Parse contacts file into two lists:
#   contacts: "name:ip:port"  — entries with ip+port and own != true
#   devices:  "name:token_set" — entries with own=true
PARSED=$(awk '
{
    sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "")
    if ($0 == "" || $0 ~ /^[\/\#]/) next
    if ($0 !~ /^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+[ \t]*=/) next

    dotpos = index($0, ".")
    eqpos  = index($0, "=")
    name   = substr($0, 1, dotpos - 1)
    field  = substr($0, dotpos + 1, eqpos - dotpos - 1)
    sub(/[ \t]+$/, "", field)
    value  = substr($0, eqpos + 1)
    sub(/^[ \t]+/, "", value); sub(/[ \t]+$/, "", value)
    sub(/^"/, "", value); sub(/"$/, "", value)

    if (field == "ip")    ip_map[name]    = value
    if (field == "port")  port_map[name]  = value
    if (field == "own")   own_map[name]   = value
    if (field == "token") token_map[name] = value
}
END {
    for (n in ip_map)
        if (port_map[n] != "" && own_map[n] != "true")
            print "contact:" n ":" ip_map[n] ":" port_map[n]
    for (n in own_map)
        if (own_map[n] == "true")
            print "device:" n ":" (token_map[n] != "" ? "yes" : "no")
}
' "$CONTACTS_FILE")

CONTACT_LIST=$(echo "$PARSED" | grep '^contact:' | sed 's/^contact://' | sort)
DEVICE_LIST=$(echo "$PARSED"  | grep '^device:'  | sed 's/^device://'  | sort)

# --- Contacts ---
if [ -z "$CONTACT_LIST" ]; then
    info "No contacts found with ip/port set."
else
    echo "  Contacts:"
    echo ""
    echo "$CONTACT_LIST" | while IFS=: read -r cname cip cport; do
        printf "    %-18s %s:%s  " "$cname" "$cip" "$cport"
        curl -s --max-time 3 "http://$cip:$cport/" >/dev/null 2>&1
        RESULT=$?
        if [ "$RESULT" -eq 28 ]; then
            printf "\033[33m!!\033[0m  timed out\n"
            printf "                       is their daemon running? is the IP/port correct?\n"
            printf "                       is the port forwarded on their router?\n"
        elif [ "$RESULT" -eq 7 ]; then
            printf "\033[33m!!\033[0m  connection refused\n"
            printf "                       machine is reachable but daemon may not be running\n"
        else
            printf "\033[32mok\033[0m  reachable\n"
        fi
    done
    echo ""
fi

# --- Devices ---
if [ -n "$DEVICE_LIST" ]; then
    echo "  Devices (own=true — they connect to this daemon, not tested outbound):"
    echo ""
    echo "$DEVICE_LIST" | while IFS=: read -r dname dtoken; do
        if [ "$dtoken" = "yes" ]; then
            printf "    %-18s token: set\n" "$dname"
        else
            printf "    %-18s \033[33m!!\033[0m  token: missing — add %s.token to contacts\n" \
                "$dname" "$dname"
        fi
    done
    echo ""
fi
