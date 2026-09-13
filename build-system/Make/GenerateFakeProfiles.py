#!/usr/bin/env python3
"""Regenerate the self-signed provisioning profiles in build-system/fake-codesigning.

rules_apple refuses to build for a physical device unless every bundle embeds a
provisioning profile, so a device build without an Apple Developer account still needs
*some* profiles. This tool produces a coherent self-signed set for an arbitrary
team id + bundle id using the repository's own certificate
(build-system/fake-codesigning/certs/SelfSigned.p12, empty password).

The profiles are not installable (the certificate is not issued by Apple); they only
make `bazel build --configuration=release_arm64` succeed so that the resulting IPA can be
re-signed for sideloading with build-system/resign-ipa.py.

    python3 build-system/Make/Make.py generate-fake-profiles \
        --teamId C67CF9S4VU --bundleId com.pikmis.lotusgram
"""

import argparse
import datetime
import os
import plistlib
import subprocess
import sys
import tempfile

# bundle id suffix -> file name, mirroring BuildConfiguration.PROFILE_NAME_MAPPING
PROFILES = {
    '': 'Telegram',
    '.Share': 'Share',
    '.Widget': 'Widget',
    '.SiriIntents': 'Intents',
    '.NotificationService': 'NotificationService',
    '.NotificationContent': 'NotificationContent',
    '.BroadcastUpload': 'BroadcastUpload',
}


def run(args, input_data=None, check=True):
    return subprocess.run(args, input=input_data, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def load_selfsigned(p12_path):
    """Return (certificate_pem, private_key_pem, certificate_der) from the p12."""
    cert = run(['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:', '-nokeys',
                '-clcerts', '-legacy'])
    key = run(['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:', '-nocerts',
               '-nodes', '-legacy'])
    cert_der = run(['openssl', 'x509', '-outform', 'DER'], input_data=cert.stdout).stdout
    return cert.stdout, key.stdout, cert_der


def build_profile_plist(team_id, bundle_id, suffix, certificate_der):
    app_id = team_id + '.' + bundle_id + suffix
    entitlements = {
        'application-identifier': app_id,
        'com.apple.developer.team-identifier': team_id,
        'keychain-access-groups': [team_id + '.*'],
        'com.apple.security.application-groups': ['group.' + bundle_id],
    }
    if suffix in ('', '.NotificationService'):
        entitlements['aps-environment'] = 'production'
    if suffix in ('', '.SiriIntents'):
        entitlements['com.apple.developer.siri'] = True

    return {
        'AppIDName': bundle_id + suffix,
        'ApplicationIdentifierPrefix': [team_id],
        'CreationDate': datetime.datetime(2026, 1, 1),
        'DeveloperCertificates': [certificate_der],
        'Entitlements': entitlements,
        'ExpirationDate': datetime.datetime(2036, 1, 1),
        'Name': 'LotusGram Fake ' + (suffix or 'App'),
        'ProvisionedDevices': ['00008120-0000000000000000'],
        'TeamIdentifier': [team_id],
        'TeamName': 'LotusGram Self-Signed',
        'TimeToLive': 3650,
        'UUID': 'FAKE0000-0000-4000-8000-{:012d}'.format(
            abs(hash((team_id, bundle_id, suffix))) % 10 ** 12),
        'Version': 1,
    }


def generate(team_id, bundle_id, p12_path, destination):
    cert_pem, key_pem, cert_der = load_selfsigned(p12_path)
    os.makedirs(destination, exist_ok=True)

    workdir = tempfile.mkdtemp()
    cert_path = os.path.join(workdir, 'cert.pem')
    key_path = os.path.join(workdir, 'key.pem')
    with open(cert_path, 'wb') as f:
        f.write(cert_pem)
    with open(key_path, 'wb') as f:
        f.write(key_pem)

    for suffix, logical_name in PROFILES.items():
        plist = build_profile_plist(team_id, bundle_id, suffix, cert_der)
        plist_path = os.path.join(workdir, 'profile.plist')
        with open(plist_path, 'wb') as f:
            f.write(plistlib.dumps(plist, fmt=plistlib.FMT_XML))

        output_path = os.path.join(destination, logical_name + '.mobileprovision')
        run(['openssl', 'smime', '-sign', '-inkey', key_path, '-signer', cert_path,
             '-in', plist_path, '-outform', 'der', '-nodetach', '-out', output_path])
        print('  wrote {}'.format(output_path))

    print('Regenerated {} self-signed profiles for {}.{}'.format(
        len(PROFILES), team_id, bundle_id))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--teamId', required=True, help='Team id to bake into the profiles.')
    parser.add_argument('--bundleId', required=True, help='Bundle id to bake into the profiles.')
    parser.add_argument('--p12', default='build-system/fake-codesigning/certs/SelfSigned.p12',
                        help='Self-signed certificate to sign the profiles with.')
    parser.add_argument('--destination', default='build-system/fake-codesigning/profiles',
                        help='Directory to write the .mobileprovision files to.')
    args = parser.parse_args()

    if not os.path.isfile(args.p12):
        print('ERROR: {} does not exist'.format(args.p12))
        sys.exit(1)

    generate(args.teamId, args.bundleId, args.p12, args.destination)


if __name__ == '__main__':
    main()
