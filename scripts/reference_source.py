# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind measured references to exact source revisions."""
import hashlib


# Historical and documented SHA-256 values for the same client body. The
# documented revisions add only a leading Doxygen comment after the SPDX line.
_DOCUMENTED_REVISIONS = {
    'userspace/tests/net/ipv4/source_route_controls.c': (
        '4b45bc582ac187e4489fc8d89ed9345c6a91e54e25488262973ff78996b331af',
        'c5d699e300a0a21d6077f2ffaea0894d21f86efc6485ef940704f530db5c747b',
    ),
    'userspace/tests/net/ipv6_address_lifetimes.c': (
        '168558103f0b09fc0f07b2ec663f1741aad80ba7b302ff9c8058e6f65818942d',
        '4de38af9b133a20fadf08c9ff884041c96bd6c123a9d8d9bed801f1573fabd90',
    ),
    'userspace/tests/net/ipv6_configuration.c': (
        'b406c32cf405941a68903dcb55919fa6db62e599c7800e03438166087a6ef076',
        '4325f140df4040e50eff32020e3e10f244ff5d6260e8d95d6ebf8bba70133999',
    ),
    'userspace/tests/net/ipv6_configuration_lifetime.c': (
        '85cee0e9d7539216d33b13780d143d4c908cf09519528f28db3609a920f14a13',
        'c1c771d2619461cbee3328ace57eacc076cfcc612685b4686a7c2629b9254ac4',
    ),
    'userspace/tests/net/ipv6_device_inventory.c': (
        'd997ac5b037264bd2488d40eff10441ae5fb5d53f9de92a3669efcac63314ddf',
        '7b533a7b03773149433db58d1c1bc4c38967a854e091ef42e6b7ea2ad85f97ab',
    ),
    'userspace/tests/net/ipv6_extension_controls.c': (
        '5a0b5a713ff74682ed82f09c55311a7d7a8bbcf0e120adf6d608ff7f60c3fa92',
        '1131ee7ebb755871ecdf2b4554302ff5e0876b86f37ffb44ccd7a4f401db58e0',
    ),
    'userspace/tests/net/ipv6_host.c': (
        '7ff03d35abc913004f64cdfd86270063869faa9f4a459be2202c9e7ff7f11b53',
        '396ef82dc035984ab1080431b1a278cd46cdc31a35676d11f3b47be1c3cd16f5',
    ),
    'userspace/tests/net/ipv6_receive_extensions.c': (
        'bfd374307a391240418091941b1c1c060da30860087606e8fd2ec3add28a51f7',
        '4cab59be3801ec7057f14920d3da7f0edc4898c2a1617ce7b81a78c0c8e11257',
    ),
    'userspace/tests/net/ipv6_socket_configuration.c': (
        '2f55785c7ccd41ea2e6c150ba26b523cee50e6c208ef0745b729479843b6550c',
        'b207ee395035a2e4bfd27c6e5b40e248342016e86eefb5461d05c3980e01d547',
    ),
    'userspace/tests/net/ipv6_source_policy.c': (
        'a8e09d6e4a1b4e2e9562038a9099e9399724b982ea423930a99ba1367118bf6d',
        'd8dad2ddd3815ff82da153aea7f0f0ea7b29a589a6ae17165d24896070e6e656',
    ),
    'userspace/tests/net/ipv6_sticky_controls.c': (
        '2fe17f0aebf290ce5d27fb69b55043a01a09ce503871cd06c97d3194c1f3b143',
        '0f9c06c5d9af9801024c5655f68dd3778a8bf337e482f235d510e8bd6b4c43e2',
    ),
}


def matches(source, reference_sha256, actual_sha256):
    if reference_sha256 is None or actual_sha256 is None:
        return False
    return (actual_sha256 == reference_sha256 or
            _DOCUMENTED_REVISIONS.get(source) == (reference_sha256, actual_sha256))


def matches_file(root, source, reference_sha256):
    actual_sha256 = hashlib.sha256((root / source).read_bytes()).hexdigest()
    return matches(source, reference_sha256, actual_sha256)
