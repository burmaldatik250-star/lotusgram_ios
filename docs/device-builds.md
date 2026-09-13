# Building an IPA that installs on a real iPhone

The Bazel build produces three different things depending on how it is invoked, and only
one of them can be installed on a physical device as-is:

| Output | How to build it (CI job) | Installs on a device? |
| --- | --- | --- |
| `.app` for the Simulator | `--configuration=release_sim_arm64` (`simulator` job) | No — Simulator only |
| Self-signed device `.ipa` | `--configuration=release_arm64` + bundled profiles (`unsigned-device` job) | Only after re-signing |
| Properly signed `.ipa` | `--configuration=release_arm64 --codesigningInformationPath=...` (`device` job) | **Yes** |

Note: `--disableProvisioningProfiles` (ad-hoc signing) is **not** a device option. rules_apple
fails the analysis of a device build without profiles with
`Building for device, but no provisioning_profile attribute was set`, so ad-hoc builds only
work for the simulator. A device build must always embed profiles — when you have no Apple
account, the bundled self-signed ones play that role.

An IPA is only accepted by a device when every bundle inside it — the app *and* each
app extension — carries a provisioning profile issued by Apple for that exact bundle id,
signed with a certificate you hold the private key for. There is no way around needing an
Apple identity; the options below differ in how much of it you provide up front.

---

## Option A — sign in CI (recommended if you have an Apple Developer account)

### 1. What you need from developer.apple.com

A **distribution** (Ad Hoc) or **development** certificate, plus one provisioning profile
per bundle. The bundle ids are derived from `bundle_id` in the build configuration
(`com.pikmis.lotusgram` by default):

| Bundle | Profile for application-identifier |
| --- | --- |
| Main app | `TEAMID.com.pikmis.lotusgram` |
| Share | `TEAMID.com.pikmis.lotusgram.Share` |
| Widget | `TEAMID.com.pikmis.lotusgram.Widget` |
| Siri intents | `TEAMID.com.pikmis.lotusgram.SiriIntents` |
| Notification service | `TEAMID.com.pikmis.lotusgram.NotificationService` |
| Notification content | `TEAMID.com.pikmis.lotusgram.NotificationContent` |
| Broadcast upload | `TEAMID.com.pikmis.lotusgram.BroadcastUpload` |

For Ad Hoc profiles, register the UDIDs of the devices you want to install on first.
Enable **Push Notifications** and **App Groups** (`group.com.pikmis.lotusgram`) on the App
IDs; push in particular is required — see *Push notifications* below.

### 2. Export the certificate

```
openssl pkcs12 -export -out signing.p12 -inkey key.pem -in cert.pem
base64 -i signing.p12 | pbcopy        # macOS
```

### 3. Add the repository secrets

| Secret | Contents |
| --- | --- |
| `IOS_CERTIFICATE_BASE64` | base64 of `signing.p12` |
| `IOS_CERTIFICATE_PASSWORD` | the p12 password (empty is fine) |
| `IOS_PROVISION_PROFILES_BASE64` | base64 of a **zip** containing the `.mobileprovision` files |
| `APPLE_TEAM_ID` | your 10 character team id |
| `IOS_BUNDLE_ID` *(optional)* | override the bundle id |
| `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` *(optional)* | your api id/hash from my.telegram.org |

Create the profiles zip with `zip profiles.zip *.mobileprovision` and base64 it the same
way as the certificate.

### 4. Run the build

Push to `main`, or use **Actions → CI → Run workflow** with `target = device`. The
`device` job stages the secrets with `build-system/prepare-codesigning.py`, imports the
certificate into a temporary keychain and builds with `--codesigningInformationPath`. The
resulting `Telegram-iOS-<build>` artifact installs on the provisioned devices.

If the secrets are not configured, the workflow automatically builds the unsigned variant
instead, so the pipeline never fails just because signing is missing.

### Locally

```
python3 build-system/prepare-codesigning.py \
    --certificatePath ~/signing.p12 \
    --certificatePassword 'hunter2' \
    --profilesPath ~/profiles \
    --output build-input/codesigning \
    --configurationOutput build-input/device-configuration.json

python3 -u build-system/Make/Make.py build \
    --configurationPath=build-input/device-configuration.json \
    --codesigningInformationPath=build-input/codesigning \
    --configuration=release_arm64 \
    --buildNumber=32785
```

`prepare-codesigning.py` prints, for every profile it was given, which bundle it will be
used for and which bundles are still missing, so a misconfigured set is visible before a
two hour build rather than after it.

---

## Option B — no Apple account: self-signed device IPA + re-sign (free Apple ID / sideloading)

rules_apple cannot produce a device build without profiles, so when you have no Apple
account the `unsigned-device` CI job embeds the bundled **self-signed** profiles
(`build-system/fake-codesigning`, regenerated for `C67CF9S4VU.com.pikmis.lotusgram` by
`generate-fake-profiles`) and signs with the bundled self-signed certificate. The artifact
is a structurally correct device IPA; iOS will not run its signature, so you re-sign it
with your own (even free) Apple ID:

```
python3 build-system/resign-ipa.py \
    --ipa Telegram.ipa \
    --output Telegram.sideload.ipa \
    --profilesPath ~/Library/MobileDevice/Provisioning\ Profiles \
    --bundleId com.yourname.lotusgram \
    --minimalEntitlements
```

The script finds the profile matching each bundle automatically, rewrites the bundle ids
onto your own prefix, replaces `embedded.mobileprovision` everywhere and signs innermost
bundles first. `--minimalEntitlements` strips the entitlements a personal team cannot be
granted (push, iCloud, app groups, Siri) — without it iOS rejects the install.

A personal Apple ID gives you profiles that expire after **7 days** and a limit of three
sideloaded apps; AltStore and Sideloadly automate the renewal. `--bundleId` must match an
App ID that exists in your (free) developer account.

If you changed `bundle_id` in `build-system/fake-codesigning-configuration.json`, keep the
self-signed profiles in sync, otherwise the device build finds no matching profile:

```
python3 build-system/Make/Make.py generate-fake-profiles \
    --teamId C67CF9S4VU --bundleId <your bundle id>
```

and set `team_id` in the same configuration to the `--teamId` you used.

---

## Push notifications

`Make.py` refuses to build when the provisioning profiles carry no `aps-environment`
entitlement, because a silently push-less build is a bad surprise. Personal-team profiles
never have one, so pass `--allowMissingPushEntitlement` to build anyway; the app will
simply not register for remote notifications.

## iCloud and Siri

`enable_icloud` and `enable_siri` in the build configuration add the corresponding
entitlements. Turn them off if your App IDs do not have those capabilities enabled, or the
signature will not match the profile:

```
python3 build-system/prepare-codesigning.py ... \
    --set enable_icloud=false --set enable_siri=false
```

---

## Why the previous CI produced nothing installable

Three separate things were wrong, all of them fixed now:

1. The workflow passed `--gitCodesigningRepository=build-system/fake-codesigning`. That
   flag makes `Make.py` run `git clone` on its value, so the build died immediately with
   `fatal: repository 'build-system/fake-codesigning' does not exist`. Local signing data
   has to be passed with `--codesigningInformationPath`.
2. `ios_application(name = "Telegram")` in `Telegram/BUILD` hardcoded
   `provisioning_profile = None`, so even a build with valid profiles shipped an ad-hoc
   signed main binary. It now references
   `@build_configuration//provisioning:Telegram.mobileprovision`.
3. `build-system/fake-codesigning` originally contained self-signed profiles for
   `C67CF9S4VU.ph.telegra.Telegraph`, which matched neither the configured `bundle_id`
   (`com.pikmis.lotusgram`) nor its (empty) `team_id`. They now are regenerated for
   `C67CF9S4VU.com.pikmis.lotusgram` so a device build embeds them.
4. An early attempt at a credential-less device IPA used
   `--configuration=release_arm64 --disableProvisioningProfiles`. That can never work:
   rules_apple fails the analysis of any device bundle without a provisioning profile
   (`Building for device, but no provisioning_profile attribute was set`). Ad-hoc signing
   is simulator-only; a device build must embed profiles.
5. The simulator job used to copy `bazel-bin/Telegram/Telegram.app`, which rules_apple does
   not emit for simulator builds. The `.app` is now unpacked from the simulator IPA.

When no profile matches the configured bundle id, the behaviour now depends on the target:
a device build exits early with a message pointing at `generate-fake-profiles`, while a
simulator build (or Xcode project generation) falls back to ad-hoc signing.
