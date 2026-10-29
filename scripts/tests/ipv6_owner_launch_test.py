# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real ownership-client argument rejection before network configuration."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class OwnershipArguments(unittest.TestCase):
    def test_retiring_owners_keep_the_fresh_candidate_unique(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-owner-inventory-') as temporary:
            program=Path(temporary)/'inventory'
            built=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                'userspace/tests/net/ipv6_owner_inventory_model.c','-o',str(program)],cwd=ROOT,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.assertEqual(built.returncode,0,built.stdout.decode(errors='replace'))
            rejected={'legacy','two-fresh','duplicate-fresh','oversized-context'}
            for kind in ('legacy','context','reverse','failed-old','old-only','wrong-state',
                         'wrong-prefix','two-fresh','duplicate-fresh','oversized-context'):
                with self.subTest(kind=kind):
                    result=subprocess.run([str(program),kind],stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,timeout=2)
                    self.assertEqual(result.returncode,int(kind in rejected),result.stdout.decode(errors='replace'))
                    self.assertIn(b'IPV6_OWNER_FAIL' if kind in rejected else b'IPV6_OWNER_INVENTORY_PASS',result.stdout)

    def test_queried_record_uses_one_complete_write(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-owner-record-') as temporary:
            program=Path(temporary)/'record'
            source=ROOT/'scripts/tests/fixtures/ipv6-owner-serial-model.c'
            built=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I',str(ROOT),
                str(source),'-Wl,--wrap=printf','-Wl,--wrap=write','-Wl,--wrap=poll',
                '-Wl,--wrap=recv','-o',str(program)],cwd=ROOT,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.assertEqual(built.returncode,0,built.stdout.decode(errors='replace'))
            result=subprocess.run([str(program)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=2)
            self.assertEqual(result.returncode,0,result.stdout.decode(errors='replace'))

    def test_both_finite_queries_precede_either_ACK_wait(self):
        source=r'''
#define _GNU_SOURCE
#define main ownership_fixture_main
#include "userspace/tests/net/ipv6_address_ownership.c"
#undef main
#include <assert.h>
#include <sys/resource.h>

static unsigned sent, received;
static unsigned char requests[2][60];

ssize_t __wrap_sendto(int fd, const void* data, size_t length, int flags,
                      const struct sockaddr* destination, socklen_t destination_length) {
    unsigned lane=fd-10;
    assert(lane<2 && sent==lane && !received && length==60 && flags==0);
    assert(destination_length==sizeof(struct sockaddr_ll));
    const struct sockaddr_ll* target=(const struct sockaddr_ll*)destination;
    assert(target->sll_ifindex==(int)lane+1);
    const unsigned char* frame=data;
    uint32_t fields[3];
    memcpy(fields,frame+24,sizeof(fields));
    assert(frame[18]==lane && frame[20]==CONFLICT && frame[21]==8 && !frame[22]);
    assert(ntohl(fields[0])==0x40 && ntohl(fields[1])==2 && ntohl(fields[2])==8);
    memcpy(requests[lane],data,60);
    sent++;
    return length;
}

int __wrap_poll(struct pollfd* descriptors, nfds_t count, int timeout) {
    if (sent!=2) {
        fputs("ACK wait before both finite queries\n",stderr);
        exit(23);
    }
    assert(count==1 && timeout==100 && descriptors[0].fd>=10 && descriptors[0].fd<=11);
    descriptors[0].revents=POLLIN;
    return 1;
}

ssize_t __wrap_recv(int fd, void* data, size_t length, int flags) {
    unsigned lane=fd-10;
    assert(sent==2 && lane<2 && received==lane && length>=60 && flags==MSG_DONTWAIT);
    unsigned char reply[60]={0};
    memcpy(reply,macs[lane],6);
    memcpy(reply+6,requests[lane],6);
    memcpy(reply+12,requests[lane]+12,8);
    reply[20]=1;
    memcpy(data,reply,60);
    received++;
    return 60;
}

int main(int argc, char** argv) {
    struct rlimit limit={0};
    assert(!setrlimit(RLIMIT_CORE,&limit));
    assert(argc==2);
    struct address_record values[2]={0};
    for (unsigned lane=0;lane<2;lane++) {
        packets[lane]=10+lane;
        indices[lane]=lane+1;
        macs[lane][0]=0x52;
        macs[lane][5]=0x10+lane;
        values[lane].flags=0x40;
        values[lane].preferred=2;
        values[lane].valid=8;
        values[lane].address.s6_addr[15]=0x23+lane;
    }
    if (!strcmp(argv[1],"sequential")) {
        control(0,CONFLICT,8,0,values);
        control(1,CONFLICT,8,0,values+1);
    } else {
        assert(!strcmp(argv[1],"paired"));
        control_pair(CONFLICT,8,0,values);
    }
    assert(sent==2 && received==2 && phases[0]==1 && phases[1]==1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='axiom64-owner-finite-pair-') as temporary:
            directory=Path(temporary);unit=directory/'pair.c';program=directory/'pair'
            unit.write_text(source)
            built=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I',str(ROOT),
                str(unit),'-Wl,--wrap=sendto','-Wl,--wrap=poll','-Wl,--wrap=recv','-o',str(program)],
                cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.assertEqual(built.returncode,0,built.stdout.decode(errors='replace'))
            before=subprocess.run([str(program),'sequential'],stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,timeout=2)
            self.assertEqual(before.returncode,23,before.stdout.decode(errors='replace'))
            self.assertIn(b'ACK wait before both finite queries',before.stdout)
            after=subprocess.run([str(program),'paired'],stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,timeout=2)
            self.assertEqual(after.returncode,0,after.stdout.decode(errors='replace'))
            self.assertEqual(after.stdout.count(b'IPV6_OWNER_CONTROL'),2)

    def test_native_child_rejects_aggregate_groups_before_configuration(self):
        for group in ('both','all'):
            with self.subTest(group=group):
                result=subprocess.run([sys.executable,'-B','scripts/ipv6_owner_test.py',
                    '--child','static','--group',group],cwd=ROOT,stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=2)
                self.assertEqual(result.returncode,2)
                self.assertIn(b'native child needs one explicit group',result.stdout)

    def test_invalid_arguments_fail_before_privileged_operations(self):
        invalid=[[],['--group'],['--group','unknown'],['--retain-exhausted-routes'],
                 ['--group','global','--unknown'],['--group','lifecycle','--group','global'],
                 ['--group','global','--retain-exhausted-routes','--duplicate'],
                 ['--unknown','global']]
        with tempfile.TemporaryDirectory(prefix='axiom64-owner-arguments-') as temporary:
            program=Path(temporary)/'client'
            result=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                'userspace/tests/net/ipv6_address_ownership.c','-o',str(program)],cwd=ROOT,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode,0,result.stdout.decode(errors='replace'))
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    result=subprocess.run([str(program),*arguments],stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=2)
                    self.assertEqual(result.returncode,1)
                    self.assertIn(b'IPV6_OWNER_FAIL known ownership group and pinned prefix policy',result.stdout)
                    self.assertNotIn(b'configuration file',result.stdout)


if __name__=='__main__':unittest.main()
