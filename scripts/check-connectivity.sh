#!/bin/sh
# check-connectivity.sh — verify router settings for rmail
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

# --- Read port from config ---
if [ ! -f "$CONFIG" ]; then
    fail "Config not found at $CONFIG"
    info "Run scripts/install.sh first."
    exit 1
fi

PORT=$(grep '^port[[:space:]]*=' "$CONFIG" 2>/dev/null \
    | sed 's/^[^=]*=[[:space:]]*//' | head -1 | tr -d '[:space:]')
if [ -z "$PORT" ]; then
    fail "Could not read port from $CONFIG"
    exit 1
fi

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

# --- Hairpin NAT test ---
# rmail uses TLS-PSK, so a plain curl will fail at the TLS layer — but that
# still means the TCP connection reached the machine, which is all we need.
# Only curl exit code 28 (timeout) means the packet was dropped by the router.
printf "  Testing hairpin NAT...  "
curl -s --max-time 2 "http://$PUBLIC_IP:$PORT/" >/dev/null 2>&1
CURL_EXIT=$?
if [ "$CURL_EXIT" -eq 28 ]; then
    warn "not supported"
    info "Your router does not loop connections from inside your LAN back"
    info "to your public IP. Contacts on the same local network should use"
    info "your local IP and add a separate contacts entry:"
    info ""
    info "  you_home.ip    = 192.168.x.x   (your local IP)"
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
