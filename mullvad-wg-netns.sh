#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2018 Daniel Gröber
# Copyright (C) 2016-2018 Jason A. Donenfeld <Jason@zx2c4.com>.
# All Rights Reserved.

# Based on https://mullvad.net/media/files/mullvad-wg.sh but modified to be
# POSIX sh compliant and easier to review. This version also supports using a
# wireguard interface in a network namespace.

die() {
	echo "[-] Error: $1" >&2
	exit 1
}

provision() {

if [ "$(id -u)" != "0" ]; then
  echo "$0 $cmd must be run as root"
  exit 1
fi

umask 077

ACCOUNT=
if [ -r "$HOME"/.mullvad-account ]; then
        ACCOUNT="$(cat "$HOME"/.mullvad-account)"
fi
if [ -z "$ACCOUNT" ]; then
        printf '[?] Please enter your Mullvad account number: '
        read -r ACCOUNT
fi

key="$(cat /etc/wireguard/mullvad-*.conf \
    | sed -rn 's/^PrivateKey *= *([a-zA-Z0-9+/]{43}=) *$/\1/ip;T;q')"

if [ -n "$key" ]; then
        echo "[+] Using existing private key."
else
        echo "[+] Generating new private key."
        key="$(wg genkey)"
fi

mypubkey="$(printf '%s\n' "$key" | wg pubkey)"

echo "[+] Submitting wg private key to Mullvad API."
res="$(curl -sSL https://api.mullvad.net/wg/ \
        -d account="$ACCOUNT" \
        --data-urlencode pubkey="$mypubkey")"
if ! printf '%s\n' "$res" | grep -E '^[0-9a-f:/.,]+$' >/dev/null
then
        die "$res"
fi
myipaddr=$res

echo "[+] Removing old /etc/wireguard/mullvad-*.conf files."
rm /etc/wireguard/mullvad-*.conf || true

echo "[+] Contacting Mullvad API for server locations."

curl -LsS https://api.mullvad.net/public/relays/wireguard/v1/ \
 | jq -r \
   '( .countries[]
      | (.cities[]
        | (.relays[]
          | [.hostname, .public_key, .ipv4_addr_in])
      )
    )
    | flatten
    | join("\t")' \
 | while read -r hostname pubkey ipaddr; do
    code="${hostname%-wireguard}"
    addr="$ipaddr:51820"

    conf="/etc/wireguard/mullvad-${code}.conf"

    if [ -f "$conf" ]; then
            oldpubkey="$(sed -rn 's/^PublicKey *= *([a-zA-Z0-9+/]{43}=) *$/\1/ip' <"$conf")"
            if [ -n "$oldpubkey" ] && [ "$pubkey" != "$oldpubkey" ]; then
                    echo "WARNING: $hostname changed pubkey from '$oldpubkey' to '$pubkey'"
                    continue
            fi
    fi

    mkdir -p /etc/wireguard/
    rm -f "${conf}.tmp"
    cat > "${conf}.tmp" <<-EOF
		[Interface]
		PrivateKey = $key
		Address = $myipaddr

		[Peer]
		PublicKey = $pubkey
		Endpoint = $addr
		AllowedIPs = 0.0.0.0/0, ::/0
	EOF
    mv "${conf}.tmp" "${conf}"
done


expiry="$(curl -s -X POST https://api.mullvad.net/rpc/ \
     -H 'content-type: application/json;' \
     --data '{ "jsonrpc": "2.0"
             , "method": "get_expiry"
             , "params": { "account_token": "'"$ACCOUNT"'" }
             , "id": 1
             }' \
| jq -r '.result')"

printf '%s\n' "$expiry" > ~/.mullvad-expiry

echo; echo
if command -v dateutils.ddiff > /dev/null 2>&1; then
    dateutils.ddiff now "$expiry" -f 'Account expires in %ddays %Hhours.' >&2
else
    printf 'Account expires on %s\n' "$(date -d "$expiry")" >&2
fi

echo; echo
echo "Please wait up to 60 seconds for your public key to be added to the servers."
}

init () {
set -x
if [ "$(id -u)" != "0" ]; then
  echo "$0 $cmd must be run as root"
  exit 1
fi

nsname=$1; shift
cfgname=$1; shift
if [ $# -gt 0 ]; then
        portnum=$1; shift
else
        portnum=0
fi
if [ $# -gt 0 ]; then
        if [ $1 = "--bridge" ] || [ $1 = "--brg" ] || [ $1 = "--br" ] || [ $1 = "-b" ]; then
                enbridge=true
                shift
        else
                echo "Not supported -- specify 'bridge' to bridge veth."
                exit 1
        fi
else
        enbridge=false
fi
parentns=${parentns:-}
wgifname="$(echo "wg-${nsname}" | cut -c1-15)"

# [Note POSIX array trick]
# Ok, this is a nasty POSIX shell trick, we use the _one_ array we have
# access to, the args, aka "$@" to store the -netns option I optionally
# want to pass to `ip` below. Since we're done with cmdline parsing at this
# point that's totally fine, just a bit opaque. Hence this comment.
#
# You're welcome.
if [ -z "$parentns" ]; then
        set --
else
        set -- -netns "$parentns"
fi

# Check for old wg interfaces in (1) current namespace,
if [ -z "$parentns" ] && [ -e /sys/class/net/"$wgifname" ] 2>/dev/null; then
        ip link del dev "$wgifname"
fi

# (2) parent namespace and
if ip netns exec "$parentns" [ -e /sys/class/net/"$wgifname" ] 2>/dev/null; then
        ip -netns "$parentns" link del dev "$wgifname"
fi

# (3) target namespace.
if ip netns exec "$nsname" [ -e /sys/class/net/"$wgifname" ] 2>/dev/null; then
        ip -netns "$nsname" link del dev "$wgifname"
fi

# See [Note POSIX array trick] above.
ip "$@" link add "$wgifname" type wireguard

if ! [ -e /var/run/netns/"$nsname" ]; then
        ip netns add "$nsname"
fi

# Move the wireguard interface to the target namespace. See [Note POSIX
# array trick] above.
ip "$@" link set "$wgifname" netns "$nsname"

# shellcheck disable=SC2002 # come on, < makes the pipeline read like shit
cat /etc/wireguard/"$cfgname" \
        | grep -vi '^Address\|^DNS' \
        | ip netns exec "$nsname"  wg setconf "$wgifname" /dev/stdin

addrs="$(sed -rn 's/^Address *= *([0-9a-fA-F:/.,]+) *$/\1/ip' < /etc/wireguard/"$cfgname")"

ip -netns "$nsname" link set dev lo up
ip -netns "$nsname" link set dev "$wgifname" up

(
    IFS=','
    for addr in $addrs; do
        ip -netns "$nsname" addr add dev "$wgifname" "$addr"
    done
)

mkdir -p "/etc/netns/$nsname"
echo "nameserver 193.138.218.74" > "/etc/netns/$nsname/resolv.conf"
#echo "nameserver 10.X.0.1" > "/etc/netns/$nsname/resolv.conf"
#echo "nameserver 8.8.8.8" > "/etc/netns/$nsname/resolv.conf"
#echo "nameserver 1.1.1.1" >> "/etc/netns/$nsname/resolv.conf"

ip -netns "$nsname" route add default dev "$wgifname"
ip -netns "$nsname" -6 route add default dev "$wgifname"

# If portnum provided, setup veth + socat
if [ "$portnum" -gt "0" ]; then
        nsid="$(ip netns list-id |
                        sed -rn 's/^nsid ([0-9]+) \(iproute2 netns name\: '"$nsname"'\)$/\1/p')"

        if $enbridge; then
                hostvpnid=1
                # Ensures nsid's 0 and 1 do not conflict with hostvpnid
                nsvpnid=`expr $nsid + 2`
                hostvpnifname="$(echo "vpnb${hostvpnid}-${nsname}" | cut -c1-15)"
                nsvpnifname="$(echo "vpnb${nsvpnid}-${nsname}" | cut -c1-15)"
                hostvpnipaddr="10.200.201."$hostvpnid
                nsvpnipaddr="10.200.201."$nsvpnid
        else
                # Also ensures always same number of digits, so same ifname len
                hostvpnid=`expr $nsid '*' 2`
                nsvpnid=`expr $nsid '*' 2 + 1`
                hostvpnifname="$(echo "vpn${hostvpnid}-${nsname}" | cut -c1-15)"
                nsvpnifname="$(echo "vpn${nsvpnid}-${nsname}" | cut -c1-15)"
                hostvpnipaddr="10.200.200."$hostvpnid
                nsvpnipaddr="10.200.200."$nsvpnid
        fi

        if [ -e /sys/class/net/"$hostvpnifname" ] 2>/dev/null; then
                ip link del dev "$hostvpnifname"
        fi

        # Ty Schnouki (https://gist.github.com/Schnouki/fd171bcb2d8c556e8fdf)
        ip link add "$hostvpnifname" type veth peer name "$nsvpnifname"
        ip link set "$hostvpnifname" up
        ip link set "$nsvpnifname" netns "$nsname" up

        if $enbridge; then
                brifname="br0-mullvad"

                if [ -e /sys/class/net/"$brifname" ] 2>/dev/null; then
                        echo "Using existing bridge.  To delete, use del to delete all netns or force bridge del."
                else
                        ip link add "$brifname" type bridge
                        ip link set dev "$brifname" up
                        ip addr add "$hostvpnipaddr/24" brd + dev "$brifname"

                        # Need to forward packets to/from this bridge to route from one netns to another
                        iptables -A FORWARD -o $brifname -m comment --comment "allow packets to pass from $brifname bridge" -j ACCEPT
                        iptables -A FORWARD -i $brifname -m comment --comment "allow input packets to pass to $brifname bridge" -j ACCEPT
                fi

                ip link set dev "$hostvpnifname" master "$brifname"
                ip netns exec "$nsname" ip addr add "$nsvpnipaddr/24" dev "$nsvpnifname"
                # ip netns exec "$nsname" ip route change 10.200.201.0/24 via "$hostvpnipaddr" dev "$nsvpnifname"
        else
                ip addr add "$hostvpnipaddr/31" dev "$hostvpnifname"
                ip netns exec "$nsname" ip addr add "$nsvpnipaddr/31" dev "$nsvpnifname"
                # ip netns exec "$nsname" ip route change 10.200.200.0/24 via "$hostvpnipaddr" dev "$nsvpnifname"
        fi

        # daemon --running  calls exit() -> want to ignore with '|| true'
        daemonrunning="$(daemon --name="socat-${nsname}" --running -v |
                        egrep 'daemon\:  'socat-${nsname}' is running \(pid [0-9]+\)')" || true
        if [ -n "$daemonrunning" ]; then
                # daemon --stop  calls exit() -> want to ignore with '|| true'
                daemon --name="socat-$nsname" --stop || true
        fi
        daemon --name="socat-$nsname" socat tcp-listen:$portnum,reuseaddr,fork tcp-connect:$nsvpnipaddr:$portnum
fi

if [ ! -z "$SUDO_USER" ]; then
  echo "sudo ip netns exec $nsname su '$SUDO_USER'"
fi
}

del() {
set -x
if [ "$(id -u)" != "0" ]; then
  echo "$0 $cmd must be run as root"
  exit 1
fi

if [ $1 = "--bridge" ] || [ $1 = "--brg" ] || [ $1 = "--br" ] || [ $1 = "-b" ]; then
        delbridge=true
else
        nsname=$1;
        delbridge=false
fi

brifname="br0-mullvad"

if $delbridge; then

        if [ -e /sys/class/net/"$brifname" ]; then
                ip link del dev "$brifname"
        fi

        if [ "$(iptables-save | grep -- "-A FORWARD -o "$brifname" -m comment --comment \"allow packets to pass from "$brifname" bridge\" -j ACCEPT")" ]; then
                iptables -D FORWARD -o $brifname -m comment --comment "allow packets to pass from $brifname bridge" -j ACCEPT
        fi

        if [ "$(iptables-save | grep -- "-A FORWARD -i "$brifname" -m comment --comment \"allow input packets to pass to "$brifname" bridge\" -j ACCEPT")" ]; then
                iptables -D FORWARD -i $brifname -m comment --comment "allow input packets to pass to $brifname bridge" -j ACCEPT
        fi

        echo "Done deleting bridge.  Not attempting anything else."
        exit 0
fi

wgifname="$(echo "wg-${nsname}" | cut -c1-15)"

nsid="$(ip netns list-id |
                sed -rn 's/^nsid ([0-9]+) \(iproute2 netns name\: '"$nsname"'\)$/\1/p')"
daemonrunning=""

if [ $nsid ]; then
        # Don't know whether made with bridge or not, so try both
        # Also ensures always same number of digits, so same ifname len
        hostvpnid=`expr $nsid '*' 2`
        hostvpnifname="$(echo "vpn${hostvpnid}-${nsname}" | cut -c1-15)"

        hostvpnbrid=1
        hostvpnbrifname="$(echo "vpnb${hostvpnbrid}-${nsname}" | cut -c1-15)"

        if [ -e /sys/class/net/"$hostvpnifname" ]; then
                ip link del dev "$hostvpnifname"
        fi

        if [ -e /sys/class/net/"$hostvpnbrifname" ]; then
                if [ "$(bridge link show dev "$hostvpnbrifname" | grep "$brifname")" ]; then
                        # Probably don't need this if deleting right after
                        ip link set dev "$hostvpnbrifname" nomaster
                fi
                ip link del dev "$hostvpnbrifname"
        fi

        # daemon --running  calls exit() -> want to ignore with '|| true'
        daemonrunning="$(daemon --name="socat-${nsname}" --running -v |
                        egrep 'daemon\:  'socat-${nsname}' is running \(pid [0-9]+\)')" || true
fi


if [ -e /sys/class/net/"$wgifname" ]; then
  ip link del dev "$wgifname"
fi

if ip netns exec "$nsname" [ -e /sys/class/net/"$wgifname" ]; then
  ip -netns "$nsname" link del dev "$wgifname"
fi

ip netns delete "$nsname"

if [ -n "$daemonrunning" ]; then
        # daemon --stop  calls exit() -> want to ignore with '|| true'
        daemon --name="socat-$nsname" --stop || true
fi

if [ -e /sys/class/net/"$brifname" ]; then
        # Only delete bridge if no devices left
        if [ -z "$(bridge link | grep "$brifname")" ]; then
                ip link del dev "$brifname"

                if [ "$(iptables-save | grep -- "-A FORWARD -o "$brifname" -m comment --comment \"allow packets to pass from "$brifname" bridge\" -j ACCEPT")" ]; then
                        iptables -D FORWARD -o $brifname -m comment --comment "allow packets to pass from $brifname bridge" -j ACCEPT
                fi

                if [ "$(iptables-save | grep -- "-A FORWARD -i "$brifname" -m comment --comment \"allow input packets to pass to "$brifname" bridge\" -j ACCEPT")" ]; then
                        iptables -D FORWARD -i $brifname -m comment --comment "allow input packets to pass to $brifname bridge" -j ACCEPT
                fi
        fi
fi
}

list() {
  echo "Configs:"
  find /etc/wireguard -name 'mullvad-*' -printf "%f\n" | column
  printf "\nNamespaces:\n"
  ip netns

  brifname="br0-mullvad"
  if [ -e /sys/class/net/"$brifname" ] && [ "$(bridge link | grep "$brifname")" ]; then
          printf "\nBridge established.\n"
  else
          printf "\nNo bridge.\n"
  fi

  printf "\nSocat Daemons:\n"
  nsnames="$(ip netns list-id |
                  sed -rn 's/^nsid ([0-9]+) \(iproute2 netns name\: (.*)\)$/\2/p')"
  for nsname in $nsnames
  do
    # daemon --running  calls exit() -> want to ignore with '|| true'
    daemonrunning="$(daemon --name="socat-${nsname}" --running -v |
        egrep 'daemon\:  'socat-${nsname}' is running \(pid [0-9]+\)')" || true

    if [ -n "$daemonrunning" ]; then
      echo "socat-$nsname daemon is running"
    fi
  done
}

set -e

cmd="${1:-provision}"; shift
"$cmd" "$@" # run $cmd with rest of args
