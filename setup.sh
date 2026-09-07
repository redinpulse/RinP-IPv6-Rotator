#!/bin/sh
# RinP IPv6 Rotator - interface setup (Linux, run as root)
#
# Two provider flavors:
#   whole-block  the entire /64 is routed to the VM (Hetzner/OVH/Vultr class)
#                -> one local route makes every address bindable
#   per-address  only addresses CONFIGURED on the interface egress (Contabo)
#                -> `--pool N` configures N addresses from the block
#
# Usage:
#   sudo ./setup.sh                     detect the global prefix, install route
#   sudo ./setup.sh 2a01:db8:1::/64     explicit block
#   sudo ./setup.sh --persist [block]   also install a systemd oneshot unit
#   sudo ./setup.sh --undo [block]      remove the local route
#   sudo ./setup.sh --check [block]     probe which source mode works (15 s)
#   sudo ./setup.sh --pool N [block]    configure N pool addresses (default 100)
#   sudo ./setup.sh --undo-pool N [block]  remove them again
set -eu

BLOCK=""
ACTION="install"
PERSIST=0
POOLN=100
while [ $# -gt 0 ]; do
    case "$1" in
        --undo)      ACTION="undo"; shift ;;
        --check)     ACTION="check"; shift ;;
        --persist)   PERSIST=1; shift ;;
        --pool)      POOLN="${2:-100}"; ACTION="pool"; shift 2 ;;
        --pool=*)    POOLN="${1#*=}"; ACTION="pool"; shift ;;
        --undo-pool) POOLN="${2:-100}"; ACTION="undo-pool"; shift 2 ;;
        --undo-pool=*) POOLN="${1#*=}"; ACTION="undo-pool"; shift ;;
        *)           BLOCK="$1"; shift ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "error: run as root"; exit 1; }

DEFAULT_IFACE=$(ip -6 route show default 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)

if [ -z "$BLOCK" ]; then
    [ -n "$DEFAULT_IFACE" ] || { echo "error: no default IPv6 route - pass the block explicitly"; exit 1; }
    BLOCK=$(ip -6 addr show dev "$DEFAULT_IFACE" scope global 2>/dev/null \
        | python3 -c "
import sys, ipaddress
best = None
for line in sys.stdin:
    parts = line.split()
    if 'inet6' in parts:
        try:
            net = ipaddress.IPv6Network(parts[parts.index('inet6') + 1], strict=False)
        except ValueError:
            continue
        if best is None or net.prefixlen < best.prefixlen:
            best = net
print(best if best else '', end='')
")
    [ -n "$BLOCK" ] || { echo "error: no global IPv6 address on $DEFAULT_IFACE - pass the block explicitly"; exit 1; }
    echo "detected block: $BLOCK (dev $DEFAULT_IFACE)"
fi
case "$BLOCK" in
    */*) ;;
    *)  BLOCK="$BLOCK/64" ;;
esac

BASE=$(python3 -c "import ipaddress,sys; print(ipaddress.IPv6Network(sys.argv[1], strict=False).network_address)" "$BLOCK")

if [ "$ACTION" = "undo" ]; then
    ip -6 route del local "$BLOCK" dev lo 2>/dev/null && echo "removed local route for $BLOCK" \
        || echo "no local route present for $BLOCK"
    exit 0
fi

if [ "$ACTION" = "check" ]; then
    IFACE="${DEFAULT_IFACE:-$(ip -6 route show local table local 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)}"
    ip -6 route replace local "$BLOCK" dev lo
    SRC=$(python3 - "$BLOCK" <<'PY'
import ipaddress, random, sys
net = ipaddress.IPv6Network(sys.argv[1], strict=False)
if net.num_addresses < 8:
    print(net.network_address + 1)
else:
    print(net.network_address + random.randrange(2, min(net.num_addresses, 2**62)))
PY
)
    echo "probe 1: unconfigured random address ($SRC) via local route - whole-block mode"
    if ping -6 -c 2 -W 3 -I "$SRC" 2606:4700:4700::1111 >/dev/null 2>&1; then
        echo "PASS (whole-block mode): the provider routes the entire block."
        echo "  use: sudo ./setup.sh && python3 rotator.py --sources block"
        exit 0
    fi
    echo "  -> no replies; trying per-address mode (configured address)..."
    TADDR="${BASE}fffe"
    ip -6 addr add "${TADDR}/128" dev "$IFACE" 2>/dev/null || true
    sleep 2
    if ping -6 -c 2 -W 3 -I "$TADDR" 2606:4700:4700::1111 >/dev/null 2>&1; then
        ip -6 addr del "${TADDR}/128" dev "$IFACE" 2>/dev/null || true
        echo "PASS (per-address mode): the provider accepts CONFIGURED addresses only."
        echo "  use: sudo ./setup.sh --pool 100 && python3 rotator.py --sources iface"
        exit 0
    fi
    ip -6 addr del "${TADDR}/128" dev "$IFACE" 2>/dev/null || true
    echo "FAIL: neither mode produced replies - the provider does not route this"
    echo "  block to you at all (single assigned address or dynamic prefix)."
    exit 1
fi

if [ "$ACTION" = "pool" ] || [ "$ACTION" = "undo-pool" ]; then
    [ -n "$DEFAULT_IFACE" ] || { echo "error: no default IPv6 route"; exit 1; }
    OP="add"
    [ "$ACTION" = "undo-pool" ] && OP="del"
    echo "$OP $POOLN pool addresses (${BASE}2 .. ${BASE}$((POOLN + 1))) on $DEFAULT_IFACE"
    N=0
    i=2
    while [ "$N" -lt "$POOLN" ] && [ "$i" -le $((POOLN + 100)) ]; do
        ip -6 addr "$OP" "${BASE}${i}/128" dev "$DEFAULT_IFACE" 2>/dev/null && N=$((N + 1))
        i=$((i + 1))
    done
    echo "done: $N addresses ${OP}-ed. rotate with: python3 rotator.py --sources iface"
    exit 0
fi

IP_BIN=$(command -v ip)
SYSCTL_BIN=$(command -v sysctl)
if ip -6 route show table local 2>/dev/null | grep -q "local $BLOCK "; then
    echo "local route already present for $BLOCK"
else
    ip -6 route add local "$BLOCK" dev lo
    echo "added local route: $BLOCK -> lo"
fi
sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null
echo "block $BLOCK is fully bindable (whole-block mode)"

if [ "$PERSIST" -eq 1 ]; then
    if [ -d /etc/systemd/system ]; then
        cat > /etc/systemd/system/rinp-rotator-setup.service <<UNIT
[Unit]
Description=RinP IPv6 Rotator - local route for source rotation
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$IP_BIN -6 route add local $BLOCK dev lo
ExecStart=$SYSCTL_BIN -w net.ipv6.ip_nonlocal_bind=1
ExecStop=$IP_BIN -6 route del local $BLOCK dev lo
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable --now rinp-rotator-setup.service >/dev/null 2>&1 || true
        echo "installed systemd unit rinp-rotator-setup.service (persists across reboots)"
    else
        echo "note: systemd not found - add these lines to rc.local or a cron @reboot:"
        echo "  $IP_BIN -6 route add local $BLOCK dev lo"
        echo "  $SYSCTL_BIN -w net.ipv6.ip_nonlocal_bind=1"
    fi
fi
