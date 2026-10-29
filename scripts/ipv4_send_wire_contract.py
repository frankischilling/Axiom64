# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind physical send and wait semantics to actual sources, programs and boot images."""
import argparse
import json
from pathlib import Path
from ipv4_receive_wire_inputs import verify as inputs, load
from ipv4_receive_wire_records import require
from ipv4_send_wire_records import read
from ipv4_send_wire_capture import verify as capture

CLIENTS={'userspace/tests/net/ipv4_send_wire.c','userspace/tests/net/ipv4_receive_wire_fixture.c',
         'userspace/tests/net/ipv4_receive_wire_fixture.h'}


def verify(directory):
    metadata,sources=inputs(directory,clients=CLIENTS,program_name='ipv4-send-wire')
    require('-pthread' in load(directory/'program.inputs.json')['command'],'actual threaded common client compilation')
    records=read((directory/'client.log').read_text(),metadata['native'],metadata['firmware'])
    if metadata['native']:
        configuration=load(directory/'native-configuration.json')
        require(records['indices']==[row['ifindex'] for row in configuration['interfaces'][1:]] and
            records['identity']['release']==metadata['native_kernel_release'],'actual native kernel and interface identities')
    physical=capture(directory,metadata,records)
    return dict(directory=str(directory),native=metadata['native'],profile=metadata['profile'],
        firmware=metadata['firmware'],transport=metadata['transport'],source=metadata['source'],source_inputs=sources,
        products=metadata['products'],physical=physical,waiting_cases=records['waiting_cases'],
        output_cases=records['output_cases'],raw_pressure_cases=records['raw_pressure_cases'],
        lifetime_cases=records['lifetime_cases'],lifetime_retired_cases=records['lifetime_retired_cases'])


def cohort(values):
    wanted={(True,link,'bios','modern') for link in ('native','static','dynamic')}
    wanted|={(False,link,firmware,transport) for link in ('static','dynamic')
             for firmware in ('bios','uefi') for transport in ('modern','legacy')}
    require(len(values)==11 and {(row['native'],row['profile'],row['firmware'],row['transport']) for row in values}==wanted,
        'complete three-native/eight-guest physical send cohort')
    require(all(row['source_inputs']==values[0]['source_inputs'] for row in values),'exact same complete source for every execution')
    natives=[row for row in values if row['native']]
    require(len({json.dumps(row['physical']['lifetime_route_policies'],sort_keys=True) for row in natives})==1,
        'all native linkages observe the same kernel lifetime policies')
    guests=[row for row in values if not row['native']]
    require(len({row['products']['kernel.elf'] for row in guests})==1,'one actual immutable guest kernel')
    return dict(passed=True,profiles=11,native_profiles=3,guest_profiles=8,ordinary_cases_each=72,
        waiting_cases_each=60,original_waiting_cases_each=24,lifetime_cases_each=36,
        retired_cases_each=28,retired_observation_seconds_each=3,
        native_retired_route_policies={row['profile']:row['physical']['retired_route_policy'] for row in values if row['native']},
        raw_pressure_cases_each=4,physical_barriers_each=816,
        native_lifetime_route_policies={row['profile']:row['physical']['lifetime_route_policies'] for row in values if row['native']},
        kernel_sha256=guests[0]['products']['kernel.elf'],full_feature_acceptance=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',type=Path,action='append',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    values=[verify(path) for path in args.case]
    result=cohort(values) if len(values)>1 else {key:value for key,value in values[0].items() if key!='source_inputs'}
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:value for key,value in result.items() if key!='source_inputs'}),flush=True)
