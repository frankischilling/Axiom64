# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise installed sessions and the selected real curl products as UID 1000."""
import shlex

from http_download.peer import PAYLOAD_SHA256

PROFILES = ('build-static', 'build-dynamic', 'runtime-static', 'runtime-dynamic')


def command(profile):
    if profile == 'runtime-dynamic':
        return '/usr/bin/curl'
    base = '/usr/share/download-fixture/'+profile
    if profile.endswith('-static'):
        return base+'/curl'
    return 'LD_LIBRARY_PATH='+base+'/lib '+base+'/loader '+base+'/curl'


def files(profiles=PROFILES):
    return [*[f'/home/admin/downloads/{profile}-lane{lane}-{scheme}.bin'
              for profile in profiles for lane in (0, 1) for scheme in ('http', 'https')],
            *[f'/home/admin/downloads/wget-lane{lane}-{scheme}.bin'
              for lane in (0, 1) for scheme in ('http', 'https', 'fallback')]]


def script(network, trust_hash, profiles=PROFILES):
    text = '''#!/bin/sh
set -eu
umask 077
export PATH=/bin:/usr/bin:/sbin
unset CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR CURL_HOME LD_PRELOAD LD_LIBRARY_PATH
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
test "$(/bin/busybox id -u)" = 1000
test "$(/bin/busybox id -g)" = 1000
mode="$1"
printf 'NORMAL_BOOT_ID '
/bin/busybox cat /proc/sys/kernel/random/boot_id
/bin/busybox mkdir -p /home/admin/downloads/deny
/bin/busybox chmod 0500 /home/admin/downloads/deny
cd /home/admin/downloads
curl() {
    case "$profile" in
'''
    for profile in profiles:
        text += '        '+profile+') '+command(profile)+' "$@" ;;\n'
    text += '''        *) exit 99 ;;
    esac
}
run() {
    label="$1"; expected="$2"; shift 2
    if curl --ipv4 --noproxy '*' --connect-timeout 4 --max-time 10 --silent --show-error --fail --write-out "\\nNORMAL_TIME $mode $label %{time_total}\\n" "$@" > "$label.stdout" 2> "$label.stderr"; then actual=0; else actual=$?; fi
    printf 'NORMAL_STATUS %s %s %s\\n' "$mode" "$label" "$actual"
    /bin/busybox cat "$label.stdout"
    /bin/busybox cat "$label.stderr"
    test "$actual" = "$expected"
    if test "$expected" != 0; then /bin/busybox grep -F "curl: ($expected)" "$label.stderr"; fi
}
check_file() {
    value="$(/bin/busybox sha256sum "$1")"
    test "${value%% *}" = '''+PAYLOAD_SHA256+'''
    test "$(/bin/busybox stat -c '%a %u %g %s' "$1")" = '600 1000 1000 1048593'
    printf 'NORMAL_FILE %s %s 600 1000 1000 1048593\\n' "$1" "${value%% *}"
}
run_wget() {
    label="$1"; expected="$2"; shift 2
    if /bin/busybox wget -q -T 8 "$@" > "$label.stdout" 2> "$label.stderr"; then actual=0; else actual=$?; fi
    printf 'NORMAL_WGET_STATUS %s %s %s\\n' "$mode" "$label" "$actual"
    /bin/busybox cat "$label.stderr"
    test "$actual" = "$expected"
}
if test "$mode" = reboot; then
'''
    for name in files(profiles):
        text += '    check_file '+shlex.quote(name)+'\n'
    text += '    value="$(/bin/busybox sha256sum /etc/ssl/cert.pem)"\n'
    text += '    test "${value%% *}" = '+trust_hash+'\n'
    text += '''    echo NORMAL_PERSISTED_BEFORE_NETWORK_PASS
fi
for attempt in $(/bin/busybox seq 1 200); do
    if /bin/busybox grep -E -q '^nameserver 10\\.23\\.[12]\\.3$' /etc/resolv.conf 2>/dev/null &&
       /bin/busybox ip addr show eth0 | /bin/busybox grep -q '10.23.1.2/24' &&
       /bin/busybox ip addr show eth1 | /bin/busybox grep -q '10.23.2.2/24'; then break; fi
    /bin/busybox sleep .1
done
/bin/busybox grep -E '^nameserver 10\\.23\\.[12]\\.3$' /etc/resolv.conf
/bin/busybox ip addr show eth0 | /bin/busybox grep '10.23.1.2/24'
/bin/busybox ip addr show eth1 | /bin/busybox grep '10.23.2.2/24'
if (echo forbidden >> /etc/ssl/cert.pem) 2> trust-write.stderr; then exit 98; fi
echo NORMAL_ORDINARY_TRUST_WRITE_DENIED
'''
    for profile in profiles:
        text += 'profile='+profile+'\ncurl --version\n'
        for lane in (0, 1):
            name = profile+'-lane'+str(lane)
            host = f'lane{lane}.axiom64.test'
            plain = f'http://{host}:{network.peers[lane]["http"].port}'
            secure = f'https://{host}:{network.peers[lane]["untrusted"].port}'
            text += 'if test "$mode" = fallback; then :\n'
            text += 'elif test "$mode" = public; then\n'
            text += f'    run {name}-public 60 --output {name}-public.bin {secure}/fixed\n'
            text += 'elif test "$mode" = missing || test "$mode" = damaged; then\n'
            text += f'    run {name}-store 77 --output {name}-store.bin {secure}/fixed\n'
            text += 'elif test "$mode" = trusted || test "$mode" = reboot; then\n'
            for scheme, url in (('http', plain), ('https', secure)):
                output = name+'-'+scheme+'.bin'
                text += f'    run {name}-{scheme} 0 --output {output} {url}/fixed\n'
                text += '    check_file /home/admin/downloads/'+output+'\n'
            text += f'    run {name}-nxdomain 6 --output {name}-missing.bin http://missing.axiom64.test:{network.peers[lane]["http"].port}/fixed\n'
            text += f'    run {name}-refused 7 --output {name}-refused.bin http://{host}:{network.refused_port(lane)}/fixed\n'
            text += f'    run {name}-unreachable 28 --connect-timeout 2 --max-time 2 --output {name}-unreachable.bin http://10.23.{lane+1}.254:80/fixed\n'
            text += f'    run {name}-permission 23 --output deny/{name}.bin {plain}/small\n'
            text += 'else exit 97; fi\n'
    for lane in (0, 1):
        host = f'lane{lane}.axiom64.test'
        plain = f'http://{host}:{network.peers[lane]["http"].port}'
        secure = f'https://{host}:{network.peers[lane]["untrusted"].port}'
        wrong = f'https://wrong{lane}.axiom64.test:{network.peers[lane]["untrusted"].port}'
        fallback = f'https://10.23.{lane+1}.1:{network.peers[lane]["fallback"].port}'
        label = f'wget-lane{lane}'
        text += 'if test "$mode" = fallback; then\n'
        text += f'    run_wget {label}-fallback 0 -O {label}-fallback.bin {fallback}/fixed\n'
        text += f'    /bin/busybox grep -F "TLS certificate validation not implemented" {label}-fallback.stderr\n'
        text += f'    check_file /home/admin/downloads/{label}-fallback.bin\n'
        text += 'elif test "$mode" = public || test "$mode" = missing || test "$mode" = damaged; then\n'
        text += f'    run_wget {label}-store 1 -O {label}-store.bin {secure}/fixed\n'
        text += 'elif test "$mode" = trusted || test "$mode" = reboot; then\n'
        for scheme, url in (('http', plain), ('https', secure)):
            text += f'    run_wget {label}-{scheme} 0 -O {label}-{scheme}.bin {url}/fixed\n'
            text += f'    check_file /home/admin/downloads/{label}-{scheme}.bin\n'
        text += f'    run_wget {label}-wrong-name 1 -O {label}-wrong.bin {wrong}/fixed\n'
        text += 'fi\n'
    text += 'echo NORMAL_PHASE_PASS "$mode"\n'
    return text
