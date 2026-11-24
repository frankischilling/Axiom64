#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    vendor/auto-eduroam/connect-eduroam.sh
# @brief   Connect to eduroam using the installed NetworkManager.
# @author  frankischilling
# @date    2026-11-23
#
# Adapted for Axiom64 from frankischilling/auto-eduroam at
# 23e25f0cdb1d87e0e3857fcc095fcc2826d9b2fe. The port uses the installed
# NetworkManager, validates the school's server, and leaves secret entry to nmcli.
# The upstream license is in LICENSE.

set -euo pipefail
export LC_ALL=C

if [[ ${1:-} == --help && $# == 1 ]]; then
    printf '%s\n' 'Usage: connect-eduroam' \
        'Connect to eduroam with PEAP/MSCHAPv2. Have your school CA certificate and server domain ready.'
    exit 0
fi
if (( $# )); then
    printf '%s\n' 'Usage: connect-eduroam' >&2
    exit 2
fi
if ! command -v nmcli >/dev/null; then
    printf '%s\n' 'NetworkManager and nmcli are required.' >&2
    exit 1
fi
if ! devices=$(nmcli --terse --escape no --fields DEVICE,TYPE device status); then
    printf '%s\n' 'Could not query NetworkManager. Use the normal installed desktop boot.' >&2
    exit 1
fi
interfaces=()
while IFS=: read -r interface type; do
    if [[ $type == wifi ]]; then
        interfaces+=("$interface")
    fi
done <<<"$devices"
case ${#interfaces[@]} in
    0)
        printf '%s\n' 'NetworkManager found no Wi-Fi devices.' >&2
        exit 1
        ;;
    1) interface=${interfaces[0]} ;;
    *)
        PS3='Choose a Wi-Fi device: '
        select interface in "${interfaces[@]}"; do
            if [[ -n $interface ]]; then
                break
            fi
        done
        [[ -n $interface ]] || exit 1
        ;;
esac

if ! networks=$(nmcli --terse --get-values SSID device wifi list ifname "$interface" --rescan yes); then
    exit 1
fi
if ! grep -Fxq eduroam <<<"$networks"; then
    printf '%s\n' 'The selected Wi-Fi device did not find eduroam.' >&2
    exit 1
fi

profile='Axiom64 eduroam'
profiles=$(nmcli --terse --get-values NAME connection show)
if grep -Fxq "$profile" <<<"$profiles"; then
    printf '%s\n' 'The Axiom64 eduroam profile already exists. Edit it or reconnect in Plasma.' >&2
    exit 1
fi
IFS= read -r -p 'School username: ' identity
IFS= read -r -p 'School CA certificate (absolute path): ' certificate
IFS= read -r -p 'Authentication server domain suffix: ' domain
IFS= read -r -p 'Anonymous identity (leave blank if unused): ' anonymous
if [[ -z $identity || $certificate != /* || ! -f $certificate || ! -r $certificate ||
      ! -s $certificate || ! $domain =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]; then
    printf '%s\n' 'Enter a username, a readable CA certificate, and the server domain from your school.' >&2
    exit 1
fi

token=$(dbus-uuidgen)
if [[ ! $token =~ ^[0-9a-f]{32}$ ]]; then
    printf '%s\n' 'Could not create a NetworkManager connection ID.' >&2
    exit 1
fi
uuid="${token:0:8}-${token:8:4}-${token:12:4}-${token:16:4}-${token:20:12}"
owner=$(id -un)
cancel_profile() {
    local status=$?
    trap - EXIT
    local existing
    if ! existing=$(nmcli --terse --get-values UUID connection show); then
        printf '%s\n' 'Could not check whether the temporary eduroam profile is still active.' >&2
    elif grep -Fxq "$uuid" <<<"$existing"; then
        printf '%s\n' 'Removing the temporary eduroam profile.' >&2
        if ! nmcli --ask --wait 30 connection delete uuid "$uuid"; then
            printf '%s\n' 'Could not remove the temporary profile. It will clear when NetworkManager restarts.' >&2
        fi
    fi
    exit "$status"
}
trap cancel_profile EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

settings=()
if [[ -n $anonymous ]]; then
    settings+=(802-1x.anonymous-identity "$anonymous")
fi
nmcli --ask connection add save no type wifi ifname "$interface" \
    con-name "$profile setup $uuid" ssid eduroam \
    connection.uuid "$uuid" connection.permissions "user:$owner" connection.autoconnect no \
    wifi-sec.key-mgmt wpa-eap 802-1x.eap peap 802-1x.phase2-auth mschapv2 \
    802-1x.identity "$identity" 802-1x.ca-cert "$certificate" 802-1x.domain-suffix-match "$domain" \
    802-1x.password-flags not-saved "${settings[@]}"
nmcli --ask --wait 60 connection up uuid "$uuid" ifname "$interface"
nmcli --ask connection modify uuid "$uuid" connection.id "$profile"
trap - EXIT
