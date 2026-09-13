#!/usr/bin/env python3
"""Re-sign a built IPA so that it can be installed on a physical device.

Use this when the IPA was produced without usable provisioning profiles, e.g. by a CI
build that ran with `--disableProvisioningProfiles`, or when you want to install a build
with a personal (free) Apple ID through AltStore, Sideloadly or `ios-deploy`.

    python3 build-system/resign-ipa.py \\
        --ipa build/artifacts/Telegram.ipa \\
        --output build/artifacts/Telegram.sideload.ipa \\
        --profilesPath ~/profiles \\
        --bundleId com.yourname.lotusgram

`--profilesPath` points at a directory containing the .mobileprovision files for the app
and its extensions (a folder of profiles downloaded from developer.apple.com, or
`~/Library/MobileDevice/Provisioning Profiles`). The profile whose
application-identifier matches each bundle is picked automatically.

Requires macOS: `codesign`, `security` and `plutil` are used for the actual signing.
"""

import argparse
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

# Entitlements that a personal (free) Apple ID cannot be granted. Keeping them in the
# signature makes iOS reject the install, so they are dropped with --minimalEntitlements.
DISALLOWED_FOR_PERSONAL_TEAM = [
    'aps-environment',
    'com.apple.developer.icloud-services',
    'com.apple.developer.icloud-container-identifiers',
    'com.apple.developer.icloud-container-environment',
    'com.apple.developer.icloud-container-development-container-identifiers',
    'com.apple.developer.ubiquity-kvstore-identifier',
    'com.apple.developer.siri',
    'com.apple.developer.usernotifications.communication',
    'com.apple.developer.usernotifications.filtering',
    'com.apple.developer.carplay-messaging',
    'com.apple.developer.networking.multicast',
    'com.apple.security.application-groups',
]

# Everything except these is stripped by --minimalEntitlements.
MINIMAL_KEEP = [
    'application-identifier',
    'com.apple.developer.team-identifier',
    'get-task-allow',
]


def fail(message):
    print('ERROR: {}'.format(message))
    sys.exit(1)


def run(args, check=True, input_data=None):
    return subprocess.run(args, check=check, input=input_data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def decode_profile(path):
    """Decode a .mobileprovision into a dict. Prefers `security cms`, falls back to openssl."""
    try:
        result = run(['security', 'cms', '-D', '-i', path])
        return plistlib.loads(result.stdout)
    except (FileNotFoundError, subprocess.CalledProcessError, plistlib.InvalidFileException):
        pass
    try:
        result = run(['openssl', 'smime', '-inform', 'der', '-verify', '-noverify', '-in', path])
        return plistlib.loads(result.stdout)
    except (FileNotFoundError, subprocess.CalledProcessError, plistlib.InvalidFileException):
        return None


def load_profiles(profile_paths):
    """Index every profile by its application-identifier."""
    profiles = {}
    for search_path in profile_paths:
        if os.path.isfile(search_path):
            candidates = [search_path]
        elif os.path.isdir(search_path):
            candidates = []
            for root, _dirs, files in os.walk(search_path):
                for name in files:
                    if name.lower().endswith('.mobileprovision'):
                        candidates.append(os.path.join(root, name))
        else:
            fail('--profilesPath {} does not exist'.format(search_path))

        for candidate in candidates:
            profile = decode_profile(candidate)
            if profile is None:
                print('  skipping {} (not a readable profile)'.format(candidate))
                continue
            app_id = (profile.get('Entitlements') or {}).get('application-identifier')
            if not app_id:
                print('  skipping {} (no application-identifier)'.format(candidate))
                continue
            # Index by bundle id (the application-identifier without the team prefix) so that
            # lookups can be done with the CFBundleIdentifier of each bundle.
            prefixes = profile.get('TeamIdentifier') or profile.get('ApplicationIdentifierPrefix') or []
            bundle_id = app_id
            for prefix in prefixes:
                if app_id.startswith(prefix + '.'):
                    bundle_id = app_id[len(prefix) + 1:]
                    break
            profiles[bundle_id] = {'path': candidate, 'profile': profile, 'app_id': app_id}
    return profiles


def certificate_common_names(profile):
    """Common names of the certificates embedded in a profile."""
    names = []
    for cert in profile.get('DeveloperCertificates', []) or []:
        pem = run(['openssl', 'x509', '-inform', 'DER', '-noout', '-subject', '-nameopt', 'oneline'],
                  input_data=bytes(cert), check=False)
        if pem.returncode != 0:
            continue
        text = pem.stdout.decode('utf-8', 'replace')
        match = re.search(r'CN\s*=\s*([^,/]+)', text)
        if match:
            names.append(match.group(1).strip())
    return names


def available_identities():
    """Signing identities present in the keychain, as {common name: full identity line}."""
    try:
        result = run(['security', 'find-identity', '-v', '-p', 'codesigning'], check=False)
    except FileNotFoundError:
        return {}
    identities = {}
    for line in result.stdout.decode('utf-8', 'replace').splitlines():
        match = re.match(r'\s*\d+\)\s+([0-9A-F]+)\s+"(.+)"', line)
        if match:
            identities[match.group(2)] = match.group(2)
    return identities


def resolve_identity(args, main_profile):
    identities = available_identities()
    if args.identity:
        if identities and args.identity not in identities:
            print('WARNING: "{}" was not listed by `security find-identity`; trying it anyway.'.format(
                args.identity))
        return args.identity

    for name in certificate_common_names(main_profile):
        if not identities or name in identities:
            return name
    if identities:
        print('WARNING: none of the profile\'s certificates is in the keychain.')
        print('         Available identities: {}'.format(', '.join(sorted(identities))))
    fail('Could not determine a signing identity; pass --identity explicitly.')


def entitlements_for(profile, bundle_id, minimal):
    """Build the entitlements plist to sign a bundle with."""
    entitlements = dict(profile.get('Entitlements') or {})
    team_ids = profile.get('TeamIdentifier') or profile.get('ApplicationIdentifierPrefix') or []
    team_id = team_ids[0] if team_ids else ''

    # The application-identifier always has to match the bundle that is being signed.
    entitlements['application-identifier'] = '{}.{}'.format(team_id, bundle_id) if team_id else bundle_id
    if team_id:
        entitlements['com.apple.developer.team-identifier'] = team_id

    if minimal:
        kept = {key: value for key, value in entitlements.items() if key in MINIMAL_KEEP}
        dropped = sorted(set(entitlements) - set(kept))
        if dropped:
            print('      dropping entitlements: {}'.format(', '.join(dropped)))
        entitlements = kept
    # Otherwise the profile's entitlements are used verbatim: a profile only ever grants what
    # the issuing team is allowed to use, so anything in it is safe to sign with.

    data = plistlib.dumps(entitlements)
    path = tempfile.mktemp(suffix='.entitlements')
    with open(path, 'wb') as f:
        f.write(data)
    return path


def read_bundle_id(app_path):
    info_path = os.path.join(app_path, 'Info.plist')
    if not os.path.isfile(info_path):
        return None
    with open(info_path, 'rb') as f:
        info = plistlib.load(f)
    return info.get('CFBundleIdentifier')


def set_bundle_id(app_path, new_bundle_id):
    info_path = os.path.join(app_path, 'Info.plist')
    with open(info_path, 'rb') as f:
        info = plistlib.load(f)
    info['CFBundleIdentifier'] = new_bundle_id
    with open(info_path, 'wb') as f:
        plistlib.dump(info, f)


def find_nested_bundles(app_path):
    """Return (bundles, binaries): nested bundles innermost-first, plus things to sign plainly."""
    bundles = []
    binaries = []

    def collect(container):
        for entry in sorted(os.listdir(container)):
            full = os.path.join(container, entry)
            if not os.path.isdir(full) and not entry.endswith('.dylib'):
                continue
            if entry.endswith('.app') or entry.endswith('.appex'):
                # Depth first, so extensions are signed before the bundle that embeds them.
                for sub in ('PlugIns', 'Watch', 'Frameworks', 'Extensions'):
                    nested = os.path.join(full, sub)
                    if os.path.isdir(nested):
                        collect(nested)
                bundles.append(full)
            elif entry.endswith('.framework'):
                binaries.append(full)
                for name in sorted(os.listdir(full)):
                    candidate = os.path.join(full, name)
                    if os.path.isfile(candidate) and not name.endswith(
                            ('.plist', '.h', '.modulemap', '.json')):
                        binaries.append(candidate)
            elif entry.endswith('.dylib'):
                binaries.append(full)

    for sub in ('Frameworks', 'PlugIns', 'Watch', 'Extensions'):
        candidate = os.path.join(app_path, sub)
        if os.path.isdir(candidate):
            collect(candidate)

    return bundles, binaries


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ipa', required=True, help='The IPA to re-sign.')
    parser.add_argument('--output', required=True, help='Where to write the re-signed IPA.')
    parser.add_argument('--profilesPath', action='append', required=True,
                        help='Directory (or file) with .mobileprovision files. Repeatable.')
    parser.add_argument('--identity',
                        help='Codesigning identity. Derived from the main profile when omitted.')
    parser.add_argument('--bundleId',
                        help='New bundle id for the main app. Nested bundles are rebased to match.')
    parser.add_argument('--minimalEntitlements', action='store_true',
                        help='Sign with only application-identifier/team-identifier/get-task-allow. '
                             'Needed for a personal (free) Apple ID.')
    args = parser.parse_args()

    if not os.path.isfile(args.ipa):
        fail('--ipa {} does not exist'.format(args.ipa))

    profiles = load_profiles(args.profilesPath)
    if not profiles:
        fail('No usable provisioning profiles were found')
    print('Loaded {} profile(s):'.format(len(profiles)))
    for bundle_id in sorted(profiles):
        print('  {}  ({})'.format(bundle_id, profiles[bundle_id]['app_id']))

    workdir = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(args.ipa) as archive:
            archive.extractall(workdir)

        payload = os.path.join(workdir, 'Payload')
        if not os.path.isdir(payload):
            fail('{} does not contain a Payload directory'.format(args.ipa))
        apps = [entry for entry in sorted(os.listdir(payload)) if entry.endswith('.app')]
        if len(apps) != 1:
            fail('Expected exactly one .app in Payload, found {}'.format(apps))
        app_path = os.path.join(payload, apps[0])

        original_bundle_id = read_bundle_id(app_path)
        if original_bundle_id is None:
            fail('Could not read CFBundleIdentifier from {}'.format(app_path))
        new_bundle_id = args.bundleId or original_bundle_id
        print('Main bundle: {} -> {}'.format(original_bundle_id, new_bundle_id))

        main_profile_entry = profiles.get(new_bundle_id)
        if main_profile_entry is None:
            fail('No provisioning profile for "{}". Available: {}'.format(
                new_bundle_id, ', '.join(sorted(profiles))))
        main_profile = main_profile_entry['profile']
        identity = resolve_identity(args, main_profile)
        print('Signing identity: {}'.format(identity))

        # Rebase nested bundle ids onto the new prefix.
        def rebase(bundle_id):
            if bundle_id is None:
                return None
            if bundle_id == original_bundle_id:
                return new_bundle_id
            if bundle_id.startswith(original_bundle_id + '.'):
                return new_bundle_id + bundle_id[len(original_bundle_id):]
            return bundle_id

        bundles, binaries = find_nested_bundles(app_path)

        print('')
        print('Signing nested binaries ({}):'.format(len(binaries)))
        for binary in binaries:
            print('  {}'.format(os.path.relpath(binary, app_path)))
            run(['codesign', '--force', '--sign', identity, '--timestamp=none', binary])

        print('')
        print('Signing nested bundles ({}):'.format(len(bundles)))
        for bundle in bundles:
            old_id = read_bundle_id(bundle)
            bundle_id = rebase(old_id)
            print('  {} ({} -> {})'.format(os.path.relpath(bundle, app_path), old_id, bundle_id))
            if bundle_id != old_id:
                set_bundle_id(bundle, bundle_id)

            entry = profiles.get(bundle_id)
            if entry is None:
                fail('No provisioning profile for nested bundle "{}"'.format(bundle_id))
            profile = entry['profile']
            shutil.copyfile(entry['path'], os.path.join(bundle, 'embedded.mobileprovision'))
            entitlements_path = entitlements_for(profile, bundle_id, args.minimalEntitlements)
            try:
                run(['codesign', '--force', '--sign', identity, '--timestamp=none',
                     '--entitlements', entitlements_path, bundle])
            finally:
                os.unlink(entitlements_path)

        print('')
        print('Signing the main bundle:')
        if new_bundle_id != original_bundle_id:
            set_bundle_id(app_path, new_bundle_id)
        shutil.copyfile(main_profile_entry['path'], os.path.join(app_path, 'embedded.mobileprovision'))
        entitlements_path = entitlements_for(main_profile, new_bundle_id, args.minimalEntitlements)
        try:
            run(['codesign', '--force', '--sign', identity, '--timestamp=none',
                 '--entitlements', entitlements_path, app_path])
        finally:
            os.unlink(entitlements_path)

        run(['codesign', '--verify', '--deep', '--strict', app_path], check=False)

        print('')
        print('Packing {}...'.format(args.output))
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        if os.path.exists(args.output):
            os.remove(args.output)
        with zipfile.ZipFile(args.output, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.write(payload, 'Payload')
            for root, dirs, files in os.walk(payload):
                for name in sorted(dirs):
                    full = os.path.join(root, name)
                    archive.write(full, os.path.relpath(full, workdir) + '/')
                for name in sorted(files):
                    full = os.path.join(root, name)
                    archive.write(full, os.path.relpath(full, workdir))

        print('')
        print('Done: {}'.format(args.output))
        print('Inspect the signature with:')
        print('  unzip -q {} -d /tmp/resigned && codesign -d --entitlements - /tmp/resigned/Payload/{}'.format(
            args.output, apps[0]))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    main()
