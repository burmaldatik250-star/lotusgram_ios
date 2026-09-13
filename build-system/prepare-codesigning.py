#!/usr/bin/env python3
"""Assemble a codesigning directory that `Make.py --codesigningInformationPath` can consume.

This is the bridge between "secrets stored in CI / a file on your Mac" and the
`profiles/` + `certs/` layout expected by build-system/Make/BuildConfiguration.py.

Typical CI usage:

    export IOS_CERTIFICATE_BASE64="..."          # base64 of the .p12
    export IOS_CERTIFICATE_PASSWORD="..."
    export IOS_PROVISION_PROFILES_BASE64="..."   # base64 of a zip with *.mobileprovision
    python3 build-system/prepare-codesigning.py \\
        --output build-input/codesigning \\
        --configurationOutput build-input/device-configuration.json \\
        --baseConfiguration build-system/fake-codesigning-configuration.json

Local usage (no base64 involved):

    python3 build-system/prepare-codesigning.py \\
        --certificatePath ~/certs/dist.p12 \\
        --profilesPath ~/profiles \\
        --output build-input/codesigning \\
        --configurationOutput build-input/device-configuration.json

The script prints which of the bundles the build needs are covered by the supplied
profiles and exits with a non-zero status when the main bundle is not covered, because
without a main-bundle profile the IPA cannot be installed on a device.
"""

import argparse
import base64
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

# Same mapping BuildConfiguration.copy_profiles_from_directory uses: the suffix of the
# profile's application-identifier relative to "{team_id}.{bundle_id}" decides which bundle
# the profile belongs to.
PROFILE_NAME_MAPPING = {
    '': 'Telegram',
    '.Share': 'Share',
    '.Widget': 'Widget',
    '.SiriIntents': 'Intents',
    '.NotificationService': 'NotificationService',
    '.NotificationContent': 'NotificationContent',
    '.BroadcastUpload': 'BroadcastUpload',
    '.watchkitapp': 'WatchApp',
    '.watchkitapp.watchkitextension': 'WatchExtension',
}

# Bundles embedded into the app by Telegram/BUILD when extensions are enabled.
REQUIRED_WHEN_EXTENSIONS_ENABLED = [
    'Telegram',
    'Share',
    'Widget',
    'Intents',
    'NotificationService',
    'NotificationContent',
    'BroadcastUpload',
]


def fail(message):
    print('ERROR: {}'.format(message))
    sys.exit(1)


def read_env(name, required=True):
    value = os.getenv(name)
    if value is None or value == '':
        if required:
            fail('Environment variable {} is not set or empty'.format(name))
        return None
    return value


def decode_base64_env(name):
    raw = read_env(name)
    # GitHub Actions secrets often carry newlines; base64.b64decode tolerates them only
    # when validate=False, which is the default.
    try:
        return base64.b64decode(raw)
    except Exception as e:
        fail('Could not base64-decode {}: {}'.format(name, e))


def read_profile_plist(path):
    """Decode a .mobileprovision into a dict. Uses openssl so it also works off macOS."""
    try:
        result = subprocess.run(
            ['openssl', 'smime', '-inform', 'der', '-verify', '-noverify', '-in', path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
    except subprocess.CalledProcessError as e:
        print('WARNING: could not parse {} ({}): {}'.format(
            path,
            e.stderr.decode('utf-8', 'replace').strip().splitlines()[-1] if e.stderr else 'unknown',
            'skipping'
        ))
        return None
    except FileNotFoundError:
        fail('openssl is required to inspect provisioning profiles but was not found on PATH')
    try:
        return plistlib.loads(result.stdout)
    except Exception as e:
        print('WARNING: {} is not a valid provisioning profile plist ({}), skipping'.format(path, e))
        return None


def collect_profile_sources(args):
    """Return a list of (display_name, bytes) for every supplied provisioning profile."""
    sources = []
    if args.profilesZipBase64Env:
        data = decode_base64_env(args.profilesZipBase64Env)
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            fail('{} does not contain a zip archive'.format(args.profilesZipBase64Env))
        for name in archive.namelist():
            if name.endswith('/'):
                continue
            if not name.lower().endswith('.mobileprovision'):
                continue
            sources.append((os.path.basename(name), archive.read(name)))
    if args.profilesPath:
        if not os.path.isdir(args.profilesPath):
            fail('--profilesPath {} is not a directory'.format(args.profilesPath))
        for root, _dirs, files in os.walk(args.profilesPath):
            for file_name in files:
                if not file_name.lower().endswith('.mobileprovision'):
                    continue
                full = os.path.join(root, file_name)
                with open(full, 'rb') as f:
                    sources.append((file_name, f.read()))
    return sources


def inspect_profiles(sources):
    """Parse every supplied profile once and report what it is."""
    parsed = []
    team_ids = set()
    tmp_dir = tempfile.mkdtemp()
    try:
        for index, (name, data) in enumerate(sources):
            probe_path = os.path.join(tmp_dir, '{}.mobileprovision'.format(index))
            with open(probe_path, 'wb') as f:
                f.write(data)
            profile = read_profile_plist(probe_path)
            if profile is None:
                continue

            for prefix in profile.get('ApplicationIdentifierPrefix', []) or []:
                team_ids.add(prefix)
            entitlements = profile.get('Entitlements') or {}
            print('  profile "{}"'.format(profile.get('Name', '<unnamed>')))
            print('    application-identifier : {}'.format(entitlements.get('application-identifier', '')))
            print('    push                   : {}'.format(
                'yes' if 'aps-environment' in entitlements else 'no'))
            print('    expires                : {}'.format(profile.get('ExpirationDate')))
            parsed.append((index, name, data, entitlements.get('application-identifier', '')))
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return parsed, sorted(team_ids)


def stage_profiles(parsed, destination, bundle_id, team_id):
    """Write the profiles that belong to this app into destination/profiles."""
    profiles_dir = os.path.join(destination, 'profiles')
    os.makedirs(profiles_dir, exist_ok=True)

    covered = {}
    prefix = team_id + '.' + bundle_id
    for index, name, data, app_id in parsed:
        if not app_id.startswith(prefix):
            print('    ignored "{}": does not start with "{}"'.format(app_id, prefix))
            continue
        base_name = app_id[len(prefix):]
        logical = PROFILE_NAME_MAPPING.get(base_name)
        if logical is None:
            print('    ignored "{}": unknown bundle suffix "{}"'.format(app_id, base_name))
            continue
        stem = name[:-len('.mobileprovision')] if name.lower().endswith('.mobileprovision') else name
        staged_path = os.path.join(profiles_dir, '{}_{}.mobileprovision'.format(index, stem))
        with open(staged_path, 'wb') as f:
            f.write(data)
        covered[logical] = staged_path
        print('    {} -> "{}" bundle'.format(app_id, logical))

    return covered


def resolve_team_id(args, team_ids_from_profiles):
    if args.teamId:
        return args.teamId
    if args.teamIdEnv:
        value = read_env(args.teamIdEnv, required=False)
        if value:
            return value
    if len(team_ids_from_profiles) == 1:
        return team_ids_from_profiles[0]
    if len(team_ids_from_profiles) > 1:
        fail('The supplied profiles belong to several teams ({}); pass --teamId to disambiguate'.format(
            ', '.join(team_ids_from_profiles)))
    fail('Could not determine the team id; pass --teamId or --teamIdEnv')


def stage_certificate(args, destination):
    certs_dir = os.path.join(destination, 'certs')
    os.makedirs(certs_dir, exist_ok=True)

    if args.certificateBase64Env:
        p12_data = decode_base64_env(args.certificateBase64Env)
    elif args.certificatePath:
        if not os.path.isfile(args.certificatePath):
            fail('--certificatePath {} does not exist'.format(args.certificatePath))
        with open(args.certificatePath, 'rb') as f:
            p12_data = f.read()
    else:
        fail('Provide the signing certificate via --certificateBase64Env or --certificatePath')

    p12_path = os.path.join(certs_dir, 'Signing.p12')
    with open(p12_path, 'wb') as f:
        f.write(p12_data)

    password = ''
    if args.certificatePasswordEnv:
        password = read_env(args.certificatePasswordEnv, required=False) or ''
    elif args.certificatePassword is not None:
        password = args.certificatePassword

    # Also expose the public part as a .cer; BuildConfiguration copies both into the
    # additional codesigning output.
    pem = subprocess.run(
        ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:' + password, '-nokeys', '-legacy'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if pem.returncode == 0 and pem.stdout.strip():
        der = subprocess.run(['openssl', 'x509', '-outform', 'DER'],
                             input=pem.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if der.returncode == 0 and der.stdout:
            with open(os.path.join(certs_dir, 'Signing.cer'), 'wb') as f:
                f.write(der.stdout)
            subject = subprocess.run(
                ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'oneline'],
                input=der.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            print('  certificate: {}'.format(
                subject.stdout.decode('utf-8', 'replace').strip() or '<unknown subject>'))
    else:
        print('WARNING: could not extract the certificate from the p12 '
              '(is the password correct?): {}'.format(
                  pem.stderr.decode('utf-8', 'replace').strip()))

    return p12_path, password


def import_into_keychain(p12_path, password, keychain_name, keychain_password):
    """Import the signing certificate into a dedicated keychain (macOS only)."""
    if sys.platform != 'darwin':
        print('Skipping keychain import: not running on macOS.')
        return False

    def security(*args, check=True):
        return subprocess.run(['security'] + list(args), check=check,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    security('delete-keychain', keychain_name, check=False)
    security('create-keychain', '-p', keychain_password, keychain_name)

    existing = security('list-keychains', '-d', 'user').stdout.decode('utf-8', 'replace')
    existing = [line.strip().strip('"') for line in existing.splitlines() if line.strip()]
    security('list-keychains', '-d', 'user', '-s', keychain_name, *existing)

    security('default-keychain', '-s', keychain_name)
    security('set-keychain-settings', keychain_name)
    security('unlock-keychain', '-p', keychain_password, keychain_name)
    security('import', p12_path, '-k', keychain_name, '-P', password,
             '-T', '/usr/bin/codesign', '-T', '/usr/bin/security')
    # Without this, codesign prompts for permission and the build hangs in CI.
    security('set-key-partition-list', '-S', 'apple-tool:,apple:', '-s',
             '-k', keychain_password, keychain_name)
    print('  imported the signing certificate into keychain "{}"'.format(keychain_name))
    return True


def write_configuration(base_path, output_path, team_id, overrides):
    if base_path and os.path.isfile(base_path):
        with open(base_path) as f:
            configuration = json.load(f)
    else:
        configuration = {}

    configuration['team_id'] = team_id
    for key, value in overrides.items():
        if value is not None:
            configuration[key] = value

    required = ['bundle_id', 'api_id', 'api_hash', 'team_id', 'app_center_id',
                'is_internal_build', 'is_appstore_build', 'appstore_id',
                'app_specific_url_scheme', 'premium_iap_product_id',
                'enable_siri', 'enable_icloud']
    missing = [key for key in required if key not in configuration]
    if missing:
        fail('The resulting configuration is missing {}: provide a --baseConfiguration'.format(
            ', '.join(missing)))

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(configuration, f, indent='\t')
        f.write('\n')
    print('  wrote {}'.format(output_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', required=True,
                        help='Directory to create the "profiles" and "certs" folders in.')
    parser.add_argument('--configurationOutput', required=True,
                        help='Where to write the build configuration json (team_id filled in).')
    parser.add_argument('--baseConfiguration', default='build-system/fake-codesigning-configuration.json',
                        help='Configuration json to copy bundle_id/api keys from.')
    parser.add_argument('--certificateBase64Env',
                        help='Name of the env var holding the base64-encoded .p12.')
    parser.add_argument('--certificatePath', help='Path to the .p12 to use.')
    parser.add_argument('--certificatePasswordEnv',
                        help='Name of the env var holding the .p12 password.')
    parser.add_argument('--certificatePassword', help='The .p12 password.')
    parser.add_argument('--profilesZipBase64Env',
                        help='Name of the env var holding a base64-encoded zip of *.mobileprovision.')
    parser.add_argument('--profilesPath', help='Directory to read *.mobileprovision files from.')
    parser.add_argument('--teamId', help='Apple team id (10 characters).')
    parser.add_argument('--teamIdEnv', help='Name of the env var holding the Apple team id.')
    parser.add_argument('--bundleId', help='Override the bundle id from the base configuration.')
    parser.add_argument('--set', action='append', default=[], metavar='KEY=VALUE',
                        help='Override any other configuration key, e.g. --set api_id=123456. Repeatable.')
    parser.add_argument('--keychainName', default='build.keychain',
                        help='Name of the temporary keychain to import the certificate into.')
    parser.add_argument('--keychainPassword', default='build',
                        help='Password for the temporary keychain.')
    parser.add_argument('--noKeychain', action='store_true',
                        help='Only stage files; do not touch the keychain.')
    parser.add_argument('--allowMissingProfiles', action='store_true',
                        help='Do not fail when the profiles do not cover every bundle.')
    args = parser.parse_args()

    if not args.certificateBase64Env and not args.certificatePath:
        fail('Provide the signing certificate via --certificateBase64Env or --certificatePath')
    if not args.profilesZipBase64Env and not args.profilesPath:
        fail('Provide provisioning profiles via --profilesZipBase64Env or --profilesPath')

    if os.path.exists(args.output):
        shutil.rmtree(args.output)
    os.makedirs(args.output, exist_ok=True)

    print('Staging the signing certificate:')
    p12_path, p12_password = stage_certificate(args, args.output)

    # bundle_id is needed to classify the profiles, so read it before staging them.
    if args.bundleId:
        bundle_id = args.bundleId
    else:
        if not os.path.isfile(args.baseConfiguration):
            fail('--baseConfiguration {} does not exist'.format(args.baseConfiguration))
        with open(args.baseConfiguration) as f:
            bundle_id = json.load(f)['bundle_id']
    print('Bundle id: {}'.format(bundle_id))

    print('Inspecting provisioning profiles:')
    sources = collect_profile_sources(args)
    if not sources:
        fail('No .mobileprovision files found in the supplied input')
    parsed, team_ids = inspect_profiles(sources)
    if not parsed:
        fail('None of the supplied files could be read as provisioning profiles')

    team_id = resolve_team_id(args, team_ids)
    print('Team id: {}'.format(team_id))

    print('Matching profiles to bundles:')
    covered = stage_profiles(parsed, args.output, bundle_id, team_id)

    missing = [name for name in REQUIRED_WHEN_EXTENSIONS_ENABLED if name not in covered]
    print('')
    print('Covered bundles : {}'.format(', '.join(sorted(covered)) or '<none>'))
    if missing:
        print('Missing bundles : {}'.format(', '.join(missing)))
        print('                  Build with --disableExtensions if you only signed the main bundle.')
        if 'Telegram' in missing and not args.allowMissingProfiles:
            fail('No provisioning profile for the main bundle ("{}"): the IPA would not install '
                 'on a device. Pass --allowMissingProfiles to continue anyway.'.format(bundle_id))

    overrides = {'bundle_id': args.bundleId}
    for item in args.set:
        if '=' not in item:
            fail('--set expects KEY=VALUE, got "{}"'.format(item))
        key, value = item.split('=', 1)
        overrides[key.strip()] = value.strip()

    print('')
    print('Writing the build configuration:')
    write_configuration(args.baseConfiguration, args.configurationOutput, team_id, overrides)

    if not args.noKeychain:
        print('')
        print('Importing into the keychain:')
        import_into_keychain(p12_path, p12_password, args.keychainName, args.keychainPassword)

    print('')
    print('Done. Build with:')
    print('  python3 -u build-system/Make/Make.py build \\')
    print('      --configurationPath={} \\'.format(args.configurationOutput))
    print('      --codesigningInformationPath={} \\'.format(args.output))
    print('      --configuration=release_arm64 --buildNumber=<number>')


if __name__ == '__main__':
    main()
