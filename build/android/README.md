# Pinned Chibaheit SFA Android RELEASE

This is a small patch layer, not a new Android fork or protocol implementation.
The default is now a non-debuggable, owner-signed release, using fork core
`4a39ff496a245e1864cdbe608cab09f5d17df9bc`
and its exact `clients/android` gitlink
`a3668ae6e4bbcb3ceff8461d0cac55d79edf504f`. The app's baseline is **1.14.1,
versionCode 734**, customized as **1.14.1-chibaheit.2, versionCode 735**. It is not official
1.14.2. Using the recorded gitlink avoids an unreviewed core/app upgrade, but
does not guarantee API compatibility: the first hosted build exposed the drift
documented below. Neither `testing` nor other PRs are synchronized by this recipe.

Official 1.14.2 would instead require reviewing core
`af6e64c3b69e6132ebaee0e1a3d24e93903f6709` with app
`fc21909df7a3f0fc9435f3866fb6a4960711aa5f` (code 739), rebasing the patch
layer, and repeating compatibility checks. Do not mix that app with this core
or relabel this build as 1.14.2. The separate Android configuration work must
also be checked against this actual binary version before phone use.

The original DEBUG recipe remains available unchanged at tooling commit
`84878b7e0340059cad7ef4e25780790247cdc79f`; it is an ephemeral-signer trial,
not an Obtainium update channel. No extra debug/release mode switches are added.
All five compatibility/identity patches remain in the release recipe.

## Manual GitHub installation boundary

`custom-android.yml.in` is **non-active build documentation**. No workflow is
installed by this PR. The current credential lacks workflow scope; do not push
workflow files with it, encode them into another active workflow, or dispatch the
existing `build.yml`.

After committing this tooling, render outside every checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/android/render_workflow.py \
  /home/hermes/outputs/sing-box-android-release \
  --installed /path/to/read-back-installed-custom-android.yml
```

Deliver both `custom-android-release-<full-tooling-SHA>.yml` and the matching
`.patch` (an update diff against the read-back installed workflow). The generated YAML
pins this tooling's full commit SHA, the full core SHA, and the verified app
gitlink; it does not read a moving `dev`/`testing` revision or accept shell inputs.

The user must manually edit **`.github/workflows/custom-android.yml`** on `testing`
(the default branch), replace it with the entire delivered YAML, and commit using
their GitHub UI authority. Use **`Update pinned Android RELEASE tooling [skip ci]`**:
the existing unsafe `build.yml` also triggers on pushes to `testing`, even if only
a workflow file changes. GitHub's `[skip ci]` directive suppresses those automatic
push/PR runs; it does **not** suppress the later explicit `workflow_dispatch`.
Do not omit this directive or combine the install with unrelated commits.
Do not paste the unified diff into the YAML editor. The patch is an
alternative review/application format, not a credential-scope workaround.
The tooling PR can remain unmerged: the workflow fetches its immutable commit.

For an already installed workflow, deliver a new revision-named YAML and a diff
against the installed file; do not overwrite the original delivery. The user
must manually **edit** `.github/workflows/custom-android.yml` on `testing` to
update the tooling pin, using **`Update pinned custom Android tooling [skip ci]`**.
Do not push that edit with this credential. Re-running the old failed run still
uses its old immutable tooling pin; only a new run after the manual update can
consume the fix.

Only **after owner key setup, manual installation, read-back comparison and
separate build authorization**, use Actions > **Custom Android RELEASE** >
Run workflow, selecting `testing`. This job does not authorize a dispatch.

Read back that workflow file before dispatch: it must equal the delivered YAML.
This preparation task does not dispatch, merge, release, or publish an APK.
The new workflow has only `workflow_dispatch`, `contents: read`, narrowly scoped signing inputs,
no cache mutation/GC, and allowlisted `upload-artifact` output. It does not
execute untrusted pull-request code. Dispatch explicitly accepts Google's
Android SDK/NDK licenses via the named SDK setup step; review those licenses first.

## Permanent signer setup (owner action, not performed by this patch)

The owner must choose/provision one permanent signing key outside this workflow.
Do not use upstream `app/release.keystore`, an ephemeral runner key, or a fallback
debug signer. Keep an encrypted offline backup of the keystore, alias, passwords
and independently obtained public certificate SHA-256; loss of the private key
breaks the update channel. Base64 is encoding, **not encryption**. Do not send
keys/passwords/tokens through chat, source, logs, artifacts or PR descriptions.

**Security setup is pending:** review found no `android-release` environment and
only repository-scoped signing secrets. The template's `environment: android-release`
declaration is **not protection**: it does not configure reviewers, branch restrictions
or migrate secrets. The parent is handling the owner's migration/security decision
separately. No environment, protection rule or secret is configured by this patch.

Before installation/dispatch, the owner must use **Settings > Environments** to
create/protect **`android-release`** and verify the saved configuration:

1. Select deployment branch/tag restrictions allowing only the **`testing` branch**,
   not arbitrary branches or tags. Verify that the policy is actually available
   for this repository/plan and that other refs are ineligible.
2. Require approval by an eligible, usable owner reviewer. For a sole-owner
   repository, leave **Prevent self-review disabled** so the owner can approve
   their own manual run; this is an approval gate, not independent two-person
   review. If independent review is required, arrange another eligible reviewer
   before proceeding. Do not configure an impossible approval requirement.
3. Provision the independently verified values below through the environment's
   masked secrets UI. Verify the secret names/scope and protection settings
   without exposing values. Only a separately authorized run can confirm that
   approval and the migrated signing inputs work end to end.
4. **After verified migration, retire the repository-scoped copies** of these
   secrets. Environment secrets take precedence for this job, but repository
   copies still allow other eligible workflows to access them without this
   environment's approval gate. Do not claim migration is secure or complete
   while those copies remain.

| Name | Owner-provided value |
| --- | --- |
| `KEYSTORE_B64` | Strict single-line base64 of the backed-up keystore (at most 1 MiB decoded; GitHub's smaller secret-size limit also applies) |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Alias: starts alphanumeric, then alphanumeric/dot/underscore/hyphen, at most 128 characters |
| `KEY_PASSWORD` | Private-key password |
| `CERT_SHA256` | Independently verified signing **certificate** SHA-256: exactly 64 contiguous hex digits or exactly 32 colon-separated hex byte pairs |

Passwords must be nonempty printable single-line values. GitHub masks secrets,
but masking is not the primary protection: scripts disable tracing, do not print
inputs, pass passwords via apksigner's `env:` sources (never `pass:` command-line
values), and suppress private signer diagnostics on error. The scripts use
`KEYSTORE_B64` only; no guessed private file path is read.

`CERT_SHA256` is mandatory protected configuration, **not** read from the APK,
its checksum, an artifact, workflow input or source checkout. Both signing and the
collector compare against it independently. An attacker replacing an APK and its
accompanying certificate text cannot replace this expected identity. Keep this
secret's provisioning independently verified against the owner's backed-up key.
It is a public fingerprint, not an APK SHA-256 and not a password.
Both accepted fingerprint formats are normalized to lowercase 64-digit hex;
mixed separators, whitespace, punctuation, missing bytes and extra bytes are
rejected. Normalization never replaces the independent expected-certificate pin
with a digest read from an APK.

Preflight runs immediately after immutable tooling checkout, before source/tool
setup. Only the separate preflight and signing steps receive all five inputs;
collection receives only the public `CERT_SHA256`. The source-build step and
`build.sh` never receive them: unsetting an inherited variable does not erase it
from the shell's initial Linux `/proc/<pid>/environ`, which a source child can
inspect. Local callers must likewise launch the build without signing inputs,
not export them around the whole recipe. No secrets are job-global or passed to
actions. Bad/missing inputs fail closed; correct presence/base64 does not prove the keystore password
or alias works until the signing step.

Step separation is **not a sandbox for untrusted same-user code**. Pinned tooling,
core/app sources and their build dependencies must be trusted and reviewed;
malicious code could persist into a later signing step on the same runner. This
change removes direct build-environment exposure, not that broader trust requirement.

Signing writes only `$RUNNER_TEMP/chibaheit-release-signing/owner.jks`, outside
the source/workspace, with directory mode 0700/file mode 0600. The shell EXIT/INT/
TERM traps remove it; a separate CI `if: always()` step repeats cleanup after
failure/cancellation. Nothing caches or archives this directory. A runner forced
off before cleanup must be discarded; never use this recipe on a shared persistent
self-hosted runner. Only hosted Ubuntu runners are supported by the template.

## Build recipe and source evidence

### Same-build Android dependency evidence

`runtime.init.gradle` is an external init script, not an upstream project patch.
`build.sh` invokes `:app:captureOtherReleaseProvenance`, which depends on
`:app:assembleOtherRelease` in the **same Gradle invocation**, with configuration
cache disabled. After assemble succeeds it reads that project's existing
`otherReleaseRuntimeClasspath` and resolvable core-library-desugaring
Configurations, not a new dependency declaration or reconstructed POM graph.
It does not change versions, dependency locks, verification metadata, protocols,
the five patches, versionCode **735**, or permanent signing. The previous 735 is
unpublished; this evidence-only rebuild needs no gratuitous version bump.

The required machine-readable graph contains selected components, variants,
capabilities, edges (including conflict-selected versions), and actual artifact
SHA-256/content-addressed copies. Local AARs are separately inventoried.
Missing/unresolved runtime or desugaring configurations, artifacts, or local
libbox fail before signing. Only stale owned graph files are removed at initialization;
the capture tree is never recursively deleted.
The capture also rejects a Configuration still in UNRESOLVED state after assemble,
rather than silently performing a new resolution. If a future AGP consumes a
detached copy instead, CI must fail and the hook must be adapted to that actual
consumer; this narrow fixture does not establish AGP 9.3.1 integration.
Supplemental Gradle POM/source queries do **not** supply the runtime graph.
Exact-coordinate `.module` files are read from Gradle's
`caches/modules-2/files-2.1/<group>/<module>/<version>/<hash>/` only when present;
binary `metadata-*` indexes and whole caches are not archived.
Unavailable POMs/modules/sources are explicit missing records, not proof of
completeness. Gradle's public resolution API does not expose repository origin;
this is explicitly unavailable, not inferred from repository order.

Available R8 text outputs, merged native/resource/asset output hashes and
allowlisted R8/native/resource task input hashes are retained. SDK platform and
candidate NDK runtime inputs have separate classifications: SDK/tool installation
does not imply incorporation. AGP directory/input coverage must be reviewed in
the first real CI capture; absent outputs are explicit. These are input evidence,
not an assertion every byte survives shrinking/packaging.

`runtime_provenance.py` rejects absent/fixture graphs and changed artifacts,
extracts bounded embedded LICENSE/NOTICE/COPYING/COPYRIGHT files, and creates a
hash-indexed **android-dependency-provenance.tar.gz nested inside the existing
source-patch-bundle.tar.gz**. Its hash is also in source-manifest.json. This keeps
the installed workflow's exact upload allowlist and full structure unchanged;
the manual UI handoff changes only the immutable tooling ref. No private
workspace, signing directory, environment dump or giant SDK/cache archive is
included. Graph paths are project-relative/redacted and URL userinfo/query
credentials are stripped from graph labels only. Original artifact/source/metadata
bytes are never rewritten: a shared Python validator scans retained raw evidence
and ZIP members, recursively including AAR `classes.jar` and nested source JARs,
before publishing the Gradle graph. Optional POM/module/source/R8
evidence containing credential URLs is omitted with an explicit nonsecret reason
and the SHA-256 of its original bytes. Required evidence fails with a sanitized
error instead. The archive validator independently rescans all public leaves,
including the graph; public Maven inputs are not implicitly trusted.
The bounded lexical scan recognizes URL userinfo and credential query/fragment
keys (including percent-encoded keys, camelCase, HTML entities, JSON ASCII escapes
and UTF-16 ASCII text). Ordinary source variable names such as `token` and safe
URLs are not redacted or modified. This is not a general secret classifier or a
decoder for arbitrarily obfuscated/encrypted source.
Uninspectable nested ZIP evidence is not certified: malformed/unsupported ZIPs
or nested inspection limits abort required evidence or omit optional evidence
with its original SHA-256 and a sanitized reason. Nested `.zip`/`.jar`/`.aar`
members must be inspectable ZIPs. Notices inside nested archives use `!/` between
archive/member names in the index; original archive bytes remain unchanged.

Capture root, referenced files, reserved notice/index paths and archive output
must have no symlink ancestors, including the final path. Checks precede reads
and writes. Archives are published only after validation, via an exclusively owned
temporary file; existing output is never overwritten and cleanup only unlinks
owned files. These checks assume a **trusted, nonconcurrent workspace and stable
inputs**: they are not race-proof against another process swapping paths between
checks and use. Do not run this collector concurrently or against a hostile
same-user filesystem.

Limits apply to each ZIP and the overall capture, including declared sizes,
actual streamed bytes and duplicate-member work. Defaults: 100,000 members per
archive / 500,000 per capture; 128 MiB per member; 512 MiB expanded per archive;
2 GiB total scanned bytes (raw files plus expanded members); 2 GiB retained raw
evidence; 1 MiB per notice / 32 MiB total notices; 32 MiB graph. ZIP nesting is
limited to 8 archive levels (the outer archive is level 1). Central-directory
bytes are capped at 16 MiB per ZIP / 64 MiB across the capture, before `ZipFile`
can allocate directory entries. A bounded precheck checks the EOCD and actual
central-directory record count/lengths, not just the declared count. ZIP64,
multidisk, noncontiguous directories and malformed directory layouts are rejected
rather than parsed permissively. Ordinary ZIP comments and data descriptors work.
Nested members are streamed to anonymous temporary files, not accumulated in
memory; directory allocations and notice retention are bounded by the shared
capture limits. Expanded bytes, members, directory bytes and notices are charged
across all nesting levels and siblings, never reset per nested archive. Temporary
disk use is also bounded by the streamed byte limits. Oversize required notices
and archives fail, rather than being partially published. Original source JARs
can be much larger than notices. A bounded URL scan rejects URLs of 64 KiB or
longer. Reads use 64 KiB chunks; a failing read can exceed a byte limit by at most
one chunk. Override positive integer limits explicitly with
`RUNTIME_PROVENANCE_LIMITS`, a JSON object using keys `archive_members`,
`capture_members`, `member_bytes`, `archive_bytes`, `capture_bytes`,
`evidence_bytes`, `notice_member_bytes`, `notice_bytes`, `graph_bytes`,
`archive_depth`, `archive_directory_bytes`, `capture_directory_bytes`.
Use the same reviewed settings for Gradle capture and release collection.
These conservative defaults still require validation against the real AGP/APK
inputs before release; synthetic AAR/JAR tests are not a full Android build.
These limits concern this Android runtime collector only, not the separate
recovered Go/native supplements.

Bundle verification must derive the exact tooling-file set from the manifest's
tooling commit, and require the nested archive if and only if
`android_runtime_provenance` is present. This tooling has 23 files, hence 25 outer
members including the manifest and runtime archive (the prior release had 20
tooling files and 21 members). Verify the inner archive hash, regular unique
allowlisted paths, exact index membership/content hashes and notice/member
relationships to the captured artifacts; do not merely increase a count or
allow arbitrary extra members. Preserve prior release reports separately.

Missing embedded notices remain explicit in the index;
review original source notices too. This is practical publication evidence,
not full legal certification or an infinite transitive audit.

Reuse the recovered Go/native source supplements from run **36287782750**
separately at final publication; do not redownload those large sources in CI.
That prior APK has no recorded full runtime graph and is **not retroactively
certified** by this change. Exact Wuffs sources have been recovered and their
SHA checks passed in the parent recovery task; Wuffs recovery is no longer a blocker.
The next real build is needed only after independent review, manual UI
tooling-pin installation/read-back, and the user's actual GitHub approval.
No merge, workflow installation, dispatch, release or APK change is authorized
by this tooling preparation.

Narrow integration regression (no Android SDK or full local Android build):

```sh
JAVA_HOME=/path/to/jdk17 GRADLE=/path/to/gradle-9.7.0/bin/gradle \
  python3 build/android/test_runtime.py -v
```

This uses a synthetic HTTP Maven repository and an isolated Gradle cache to
exercise real pinned Gradle APIs, conflict selection, edges/variants, local AARs,
POM/module/source retrieval, cache layout, hashes, notices, tamper rejection and
missing-graph failure. Isolated sentinel tests reject symlink ancestors before
outside reads/writes; tiny compressed fixtures exercise aggregate limits without
large expansions. Actual raw POM/module/source credentials are omitted and the
resulting archive is inspected for leaks and unchanged original hashes.
Fixture mode is marked and rejected by release collection;
the fixture's archive-validator branch explicitly uses synthetic data, not an
Android build result. Existing collector unit tests mock this boundary explicitly.

`manifest.json` is the source/toolchain/patch-order contract. On a fresh hosted
Ubuntu 24.04 runner (at least 8 GB RAM; public standard runners have more), the
workflow installs Go **1.26.8**, Temurin **17**, SDK **platforms;android-37.1**
and **platforms;android-36** (the `libxposed-api` module), build-tools
**37.0.0**, NDK **28.0.13004108**, and command-line tools **12266719**.
App Gradle **9.7.0**, AGP **9.3.1**, and Kotlin **2.4.10** come from the
pinned app, not guessed older Android defaults. The wrapper distribution SHA-256
is added by the identity patch. The core's Go minimum is 1.25.5.

`build.sh` follows `Makefile:lib_install` exactly: install SagerNet `gomobile`
and `gobind` at **v0.1.13** (tag resolves to
`9f03b8f25789099c5c8abef4a02085da783ba923`), then run:

```sh
go run ./cmd/internal/build_libbox -target android -platform android/arm64
cp libbox.aar libbox-legacy.aar clients/android/app/libs/
cd clients/android
./gradlew --no-daemon --max-workers=2 \
  --no-configuration-cache --init-script /path/to/tooling/build/android/runtime.init.gradle \
  '-Dorg.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=1g -Dfile.encoding=UTF-8' \
  -Pkotlin.compiler.execution.strategy=in-process :app:captureOtherReleaseProvenance
```

Use `build.sh`, not these excerpted commands alone: it validates pins, applies
patches, checks the SDK and Go, unsets `LOCAL_PROPERTIES`, and rejects any app
`local.properties` or Play credential file. Supply `ANDROID_HOME`; do not create
`sdk.dir` properties. The patch binds debug signing explicitly to the SDK debug
configuration even if signing properties accidentally exist. Release explicitly
has `isDebuggable = false` and `signingConfig = null`; the upstream release
signing configuration is removed entirely. The upstream
`app/release.keystore` is never opened, used, copied, or uploaded.

`build_libbox` automatically copies to **`../sing-box-for-android/app/libs`**,
not this repository's submodule. The explicit copy is therefore essential.
Both API-24 main and API-21 legacy AARs are produced by upstream; only the main
AAR is linked into `OtherRelease`. The legacy builder excludes
`with_naive_outbound`. Gradle is limited to two workers/4 GiB heap; Go concurrency
is two. A full build is deliberately not run locally.

The original core builder already includes `with_tailscale`, but **does not
include `with_gvisor`** at this pin. The single-line core build patch adds it:
the pinned `sing-tun` `stack_gvisor.go` requires that tag. All effective tags
are recorded and checked by tests. No Shadowsocks or Tailscale implementation
is duplicated. The shallow, tag-free core checkout gets only the local
manifest's `local_version_tag` (`v1.14.1-chibaheit.2`) for `build_shared.ReadTag`, because fork `build-*` tags
are not semantic versions. This tag is never pushed. No
`update_android_version --ci` or dependency-upgrade command runs.

## Patch audit

1. Core build patch: enable existing gVisor implementation.
2. App identity patch: package **io.chibaheit.sfa**, visible **Chibaheit SFA**
   in every existing app-name locale, custom version, arm64-only split with
   universal disabled, wrapper checksum, build-tools pin, explicit debug signing
   and unsigned non-debuggable release configuration.
   Source namespace/classes remain **io.nekohasekai.sfa** for JNI/API compatibility.
3. Update patch: a `CUSTOM_BUILD` compile-time flag hides custom-updater UI,
   prevents launch checks and first-run update prompts, rejects direct GitHub
   checks and Vendor download/install calls, and cancels/skips scheduled work.
   Both GitHub and F-Droid routes are blocked before fetching. A manual check
   reports why updates are disabled instead of claiming the app is current.
4. VPN patch: throw `IOException` when `VpnService.protect(fd)` returns false;
   also brand Android's VPN session. Upstream otherwise ignores that boolean.
   `experimental/libbox/platform.go` declares an error-returning callback,
   `service.go` returns it, and `route/network.go` plus
   `protocol/tailscale/system_binding.go` return the error through socket control.
   SagerNet gomobile's pinned `bind/genjava.go` transports Java exceptions into
   Go errors via `go_seq_get_exception` in `bind/java/seq_android.c.support`.
   This is a narrowly justified fail-closed change, **not proof of phone behavior**.
5. Pinned libbox API compatibility: replace the two stale power-report promotion
   calls with `discardPowerReportDraft`, as upstream app commit
   `38c102a46990077d94dc53c4350b4d86ef8e373b` does. Core commit
   `153c0cc32ba12234861ee541dc21d7e8b4c6a2be` removed promotion in favor of
   discarding unfinished drafts; completed reports are still finalized by
   `Recorder.Close`. Explicitly return false for `usePlatformAutoRedirect` and
   throw on `createAutoRedirect`: this pinned app has no root auto-redirect
   Binder implementation. The core's platform stub uses the same capability
   pattern. This preserves the non-root `VpnService` trial and does not implement
   root auto-redirect or silently create a successful session. The approved
   Android configuration excludes `auto_redirect`; supporting the newer root
   feature would require a separately reviewed app upgrade/backport, not this fix.

Provider authorities (`.cache`, `.workingdir`, `.XposedService`, `.shizuku`)
already use `${applicationId}`; callers use runtime package names or
`BuildConfig.APPLICATION_ID`. Relative manifest class names resolve through the
unchanged namespace. Root installer reflection intentionally names a source
class, not an installation package. VPN include/exclude-app handling uses the
runtime package. Package-scoped close/USB-permission broadcasts and explicit
USBIP/Taildrop service intents remain scoped; their source action constants need
not be renamed. The non-exported install-result receiver uses the old action
string, but the updater is gated and installation callback targets it explicitly.

`sing-box://import-remote-profile`, `.bpf`/content/file associations and QR import
remain intentionally compatible with official profile links. With both apps
installed Android may show a chooser: explicitly select **Chibaheit SFA**.
They are not unique fork deep links. Notification fallback text and diagnostic
protocol names can still say `sing-box`; launcher name and VPN session are branded.
Coexistence does not permit two simultaneous Android VPN owners.

## Artifacts, signing and reproducibility limits

The pinned app's `app/build.gradle.kts` defines flavor `other`, build type
`release` and ABI splits. AGP's output directory is therefore
`clients/android/app/build/outputs/apk/other/release`. Its output-name callback
removes `-other` and `-release`; **do not search for a `*-release.apk` filename**.
For this version the unsigned name is expected to be
`SFA-1.14.1-chibaheit.2-arm64-v8a-unsigned.apk`. `signing.py` instead reads actual
`output-metadata.json`, requires `variantName=otherRelease`, exact identity/
version/ABI, one basename ending `-unsigned.apk` and exactly one APK in that
directory. This source-derived path still needs confirmation in the first real
release CI build; no local SDK/Gradle build was performed.

After `build.sh`, run `bash build/android/sign.sh CORE SIGNED_OUTPUT`, then
`python3 build/android/collect.py CORE TOOLING SIGNED_OUTPUT ARTIFACTS` in the
controlled environment shown in the template. `SIGNED_OUTPUT` must be fresh
and outside the core checkout. `sign.sh` rejects an already signed input, checks
16 KiB native alignment using pinned `zipalign -c -P 16 4`, signs into a separate
directory, verifies the signature/certificate, then rechecks alignment.
The official build-tools **37.0.0** `lib/apksigner.jar` SHA-256 is enforced
before signing and collection. Signing enables v1/v2/v3 and disables the v4
sidecar. Release verification requires **v2**, not merely jarsigner/v1.

`collect.py` accepts only the separate `SIGNED_OUTPUT/release.apk`,
checks package/version/label and rejects `application-debuggable` with the pinned SDK's `aapt`, verifies
the signature using `apksigner`, and checks **every native .so is arm64-v8a
AArch64 ELF64**, including `libbox.so`. It rejects universal or mislabeled APKs.
Artifacts are **`Chibaheit-SFA-1.14.1-chibaheit.2-arm64-v8a-RELEASE.apk`**,
`SHA256SUMS`, signing-certificate SHA-256,
source manifest (including tooling commit, patch hashes, actual signed APK SHA-256,
certificate, `debuggable=false` and `otherRelease`), source patch bundle,
and immutable core/app source archives with licenses. No whole workspace,
build log, key, or credential is uploaded. Source archives contain original
unpatched HEAD blobs; apply the recorded patches to reconstruct the custom source.
Signing material is excluded by name before `git archive`, not removed afterward.
Only tracked, allowlisted public tooling files enter the patch bundle; keystores,
local.properties, signing `.env` files, signenv/tempkeys directories and untracked
workspace files are excluded. APK checksums are computed from the final signed
bytes independently of the certificate digest.

These are reconstructible source pins, not a claim of bit-for-bit reproducibility:
Temurin 17 patch updates, hosted runner image revisions and remote Gradle/Maven
transitive artifacts are not all content-locked. Go modules are checksum-pinned;
the archives include `go.mod`/`go.sum`, Gradle files and wrapper, third-party source
and licenses. Dependency downloads still require the recorded public repositories.
Before any redistribution, retain the sources and required transitive dependency
sources/licenses beyond the artifact's **14-day** retention, review GPL-3.0 and
other license obligations, and provide corresponding source alongside binaries.
This workflow does not authorize or perform distribution.

**One-time DEBUG migration:** a code-734 trial signed by the old ephemeral debug
key cannot upgrade in place to a different permanent signer. Increasing the code
does not fix `INSTALL_FAILED_UPDATE_INCOMPATIBLE`. Unless the owner independently
has that exact old private key, securely export and check profiles/configuration,
then plan one authorized uninstall/reinstall of `io.chibaheit.sfa`. Uninstall
deletes private data, preferences and VPN grants. Exports must **not** be assumed
to include Tailscale node identity/state; re-enrollment and stale-node cleanup may
be necessary. Keep exports private. No phone operation is performed here.

Keep application ID and permanent signer unchanged. `previous_version_code`
records the highest previously distributed custom code (currently 734);
`version_code` must exceed it and cannot exceed Android's limit. Codes below or
equal to 734 are rejected. For the next update record 735 as previous, use at least
736, advance the `-chibaheit.N` counter, update `version.properties` in the identity
patch and manifest version/tag together. Artifact names and build's local core tag
are derived from the manifest, not a fixed .2 constant. If another custom build
was distributed, exceed its code instead. Official app code 739 has a different
application ID and is not this fork's floor. No silent upstream sync is permitted.

## Obtainium and separate release publication

An Actions artifact is an expiring authenticated ZIP, **not** an Obtainium release
source. The build token stays read-only, including artifact upload via Actions'
artifact service; it cannot publish releases. After owner setup and an authorized
successful CI build, the parent must separately verify the downloaded APK with
the pinned verifier and independently supplied `CERT_SHA256`, inspect package/
code/version/non-debuggable/arm64 identity, check `SHA256SUMS` and provenance pins,
and preserve corresponding sources/licenses before any publication.

Only then, with separate publication authorization, the parent may use `gh release`
with the existing repository credential (workflow scope is not required) to
publish the allowlisted APK, checksums, public certificate, source manifest,
patch bundle and source archives. Use **both tag and release title**
`android-sfa-v1.14.1-chibaheit.2`, targeting the reviewed tooling commit; initially
**prerelease=true, draft=false, make_latest=false** (`gh release create` supports
`--prerelease --latest=false`). Never overwrite a released APK/tag or desktop
release. Obtainium cannot work until that non-draft release asset actually exists.
Publication, merge, workflow installation and dispatch remain owner/parent steps.

In Obtainium, add **`https://github.com/Chibaheit/sing-box`** with these settings:

| English UI setting | Value |
| --- | --- |
| Include prereleases | On |
| Fallback to older releases | On |
| Filter release titles by regular expression | `^android-sfa-v[0-9]+\.[0-9]+\.[0-9]+-chibaheit\.[0-9]+$` |
| Filter APKs by regular expression | `^Chibaheit-SFA-[0-9]+\.[0-9]+\.[0-9]+-chibaheit\.[0-9]+-arm64-v8a-RELEASE\.apk$` |
| Sort method | Release date (`date`) |
| Verify the 'latest' tag | Off |
| Use release title as version string | Off |
| Trim version string with RegEx | `[0-9]+\.[0-9]+\.[0-9]+-chibaheit\.[0-9]+$` |
| Track-only | Off |

Leave extraction match group blank (whole match), APK-filter inversion off,
ZIP/tarball inclusion off and release-date-as-version off. Both title and tag
must use the Android prefix: the title filter checks release `name`, only falling
back to `tag_name` if the title is blank. Keep older-release fallback on so newer
desktop releases or incomplete Android releases do not hide a valid older APK.
The extracted version includes the fork counter and matches APK `versionName`.
Public releases require no GitHub token on the phone.

These labels/keys and semantics were verified in Obtainium source at
[`af286fa8d31d7406d6db167e2314d376d74f7696`](https://github.com/ImranR98/Obtainium/tree/af286fa8d31d7406d6db167e2314d376d74f7696),
specifically `lib/app_sources/github.dart`, `app_source.dart`,
`lib/services/apk_filter_service.dart` and `assets/translations/en.json`.
They are settings, not a verified import-JSON schema; none is invented here.
Installed Obtainium version and phone runtime behavior are still untested.

## Validation and upgrade procedure

The following hosted-build history concerns the **older DEBUG recipe**, not a
successful RELEASE build. The later DEBUG run `36284612324` did publish an Actions
artifact, but no release APK. This patch has only source/fixture validation until
the owner installs the workflow, provisions secrets and authorizes release CI.

### First hosted build: iteration 1

Run `36280746159`, job `108511965012`, completed both arm64 libbox AARs and
entered Gradle 9.7.0. Its first actual errors were:

```text
2026-09-27T00:00:29.5792265Z BoxService.kt:98:16 Unresolved reference 'promotePowerReportDraft'.
2026-09-27T00:00:29.5801664Z BoxService.kt:296:20 Unresolved reference 'promotePowerReportDraft'.
2026-09-27T00:00:29.5803662Z > Task :app:compileOtherDebugKotlin FAILED
```

The same compilation reported that both `ProxyService` and `VPNService` lacked
`createAutoRedirect(ByteArray!, AutoRedirectHandler!): AutoRedirectSession!`
and `usePlatformAutoRedirect(): Boolean`. These are core/app API drift, not
Node/setup-java/AGP deprecation warnings or an AAR compiler failure. No APK was
verified or uploaded; the run's artifact count was **0**.

The optional compiler regression below uses Kotlin **2.4.10** and a JDK **17**.
It projects the actual patched app calls and override bodies into a small JVM
fixture, with Java ABI declarations checked against the pinned Go declarations.
It reproduces all of the above Kotlin errors before patch 0004, compiles after
the patch, and executes both service projections to verify that unsupported
auto-redirect throws. It does **not** compile complete Android services, generate
an AAR, assemble an APK, or prove on-device behavior.

### Second hosted build: iteration 2

Run `36281916905`, job `108515262260`, used tooling
`69c8b2714f9943f6ad54c6b57b4bdad90dad081a` from the installed workflow at
`2de276b12e5d8e6c29d4cb9e174f9fae741923d5`. Patch 0004 fixed compilation:

```text
2026-09-27T00:25:58.2326185Z > Task :app:packageOtherDebug
2026-09-27T00:25:58.2332712Z > Task :app:assembleOtherDebug
2026-09-27T00:25:58.2341674Z BUILD SUCCESSFUL in 5m 40s
2026-09-27T00:25:59.8065791Z     fingerprint = certificate_digest(report)
2026-09-27T00:25:59.8071749Z ValueError: Expected exactly one verified signing certificate
```

This is a distinct collector failure, not another compile error. Reaching that
line proves source provenance, APK count, package/version/label/debug, ABI/ELF
checks and the `apksigner verify` subprocess completed successfully. It does
not mean collection completed: no fingerprint/provenance bundle was produced,
upload was skipped, and Actions returned `{"total_count":0,"artifacts":[]}`.
The hosted runner finished and this recipe has no APK cache or alternate upload.
There is no identified salvage path; do not claim a downloadable or independently
reverified sing-box APK.

The old collector captured but never printed the signing report. Its exact
contents and ephemeral certificate digest cannot be recovered from these logs.
An independently confirmed parser incompatibility is that build-tools **37.0.0** reports a
single ordinary signer as `V3.0 Signer:` (or `V2 Signer:` / `V1 Signer:`), not
`Signer #1`. This is a **probable explanation, not a proven exact cause of the
lost CI report**. It applies to ordinary single-signer reports without rotation;
no signing recipe or package/signature/architecture relaxation is needed.
The cryptographic subprocess check and all APK/source/key-exclusion checks remain.

#### Supported signing-report contract

The collector parses the pinned `apksigner verify --verbose --print-certs`
stdout only **after the subprocess exits zero**. A nonzero exit remains fatal,
even with successful-looking stdout; parsing does not perform cryptographic
verification or authenticate arbitrary text. The review's synthetic ambiguous
reports expose parser-contract bugs, not a demonstrated cryptographic bypass.

The small parser requires exactly one `Verifies` and `Number of signers: 1`.
It supports contiguous certificate records scoped by `V1 Signer:`, `V2 Signer:`
or `V3.0 Signer:`; complete legacy `Signer #1` records are also supported, but
mixing legacy and scheme scopes is rejected as ambiguous. Each record starts at
`certificate DN` and must contain exactly one of every field emitted by this
pinned verbose format: certificate DN, certificate SHA-256/SHA-1/MD5, key
algorithm, positive key size in bits, and public-key SHA-256/SHA-1/MD5.
Digests must be fixed-length hexadecimal (case is normalized); algorithms are
limited to RSA, EC and DSA. DN and other non-digest values compare exactly,
without DN canonicalization. The trial uses the SDK's ordinary RSA debug key.

Complete repeated records, including V2/V3 records, represent **one signer only
when every certificate and public-key field agrees**, not merely the SHA-256.
An explicit second signer is rejected even with the same digest. Unknown scopes,
rotation/source-stamp records, partial records (including SHA-512-only or DN-only
extra records), missing digests, duplicate fields, interleaved scopes and any
conflicting DN/algorithm/key/digest fail closed. Matching digest lines alone
are neither counted as signers nor used to discard other evidence.

Only the known verbose status lines are accepted before records; duplicate or
contradictory headers, verified v3.1/v3.2 rotation or SourceStamp, control
characters, warnings and other unknown stdout fail with explicit errors.
This intentionally is not a general parser for all apksigner versions, rotations,
certificate types or warning formats; newly encountered formats need a captured
report and review, not a permissive fallback. On a parse failure the collector
logs the public report as one JSON-escaped line (including escaped control
characters), then rethrows before creating artifacts. It neither reads nor
logs a private key.

`fixtures/apksigner-37-single-signer.txt` is unmodified output of the actual
`verify --verbose --print-certs` command on AOSP's **prebuilt test APK**
`golden-aligned-v1v2v3-out.apk`, not output from the lost CI APK or a fabricated
sing-box artifact. Fixture origin:
`https://android.googlesource.com/platform/tools/apksig/+/184702d9d18877edf9e5296c4e191cf0aa2b5fbb/src/test/resources/com/android/apksig/golden-aligned-v1v2v3-out.apk`
(Git blob `e82f67be2a8825676255ef207c8a3a03c2661c91`).
The official `https://dl.google.com/android/repository/build-tools_r37_linux.zip`
has repository-advertised SHA-1 `70954e99f4c3d9d46ee70fa32624672fe7cd6ebe`;
its `android-37.0/lib/apksigner.jar` has SHA-256
`2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180`.
Two additional unmodified reports, `fixtures/apksigner-37-v1-signer.txt` and
`fixtures/apksigner-37-v2-signer.txt`, were captured with the same verifier/JDK
from `golden-aligned-v1-out.apk` (Git blob
`403e45a2f7f47032bcd2a1a410a310c31030d76e`) and
`golden-aligned-v1v2-out.apk` (Git blob
`1c0edeb67b8bbd78f279b1e9b25874a78d478ad9`) in that same AOSP directory/revision.
All three fixtures were compared byte-for-byte with fresh command output during
the review fix. They show individual scheme labels; the repeated same-signer
multi-scheme regression is explicitly **synthetic**, not claimed captured output.

Only this verifier was extracted and run with the existing JDK 17; no full SDK,
NDK, Gradle build or local sing-box APK was installed/generated. To recapture
each fixture, substitute its prebuilt APK filename:

```sh
java -jar /path/to/apksigner.jar verify --verbose --print-certs \
  /path/to/golden-aligned-v1v2v3-out.apk
```

The original regression reproduces the same exception text as CI on the real V3
report before the label fix and passes afterward; it does not recover CI stdout.
The independent-review regressions first fail on PR5 head
`79eb564937ca89c1679f7d63e7ddfa254cf85334`: repeated identical scheme records are
incorrectly rejected while unsupported extra signer/DN/algorithm records are
ignored. They pass with scoped, complete-record identity checks. Negative tests
retain rejection of malformed/multiple signers, mismatched APKs and failing
signature commands before artifact creation, even if the failed command returns
a valid-looking report.
The next real CI collection still requires the reviewed manual tooling-pin update
described above; re-running the old immutable run cannot use this fix.

### Local checks

The script suite needs Python 3.10+, Git and PyYAML 6.0.3 for release workflow
checks (CI installs it in an isolated temporary venv), with a local copy of both
source objects; it fetches them into isolated temporary repositories:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/android/test_scripts.py \
  --core-source . --app-source clients/android -v
PYTHONDONTWRITEBYTECODE=1 python3 build/android/test_release.py -v
bash -n build/android/build.sh build/android/sign.sh
shellcheck build/android/build.sh build/android/sign.sh
actionlint /outside/repo/delivery/custom-android-release-FULL_SHA.yml
python3 build/android/validate_workflow.py /outside/repo/delivery/custom-android-release-FULL_SHA.yml
```

The default local commands and the template's CI test step **skip** real fixture
signing and the optional compiler test because their tool/fixture arguments are
not supplied. Passing that default suite is not all-coverage evidence; record
executed and skipped counts separately.

To run the narrow compiler regression separately, supply an existing Kotlin 2.4.10
compiler distribution (no SDK, NDK, Gradle or full local build is needed):

```sh
JAVA_HOME=/path/to/jdk-17 PYTHONDONTWRITEBYTECODE=1 \
  python3 build/android/test_scripts.py \
  --core-source . --app-source clients/android \
  --kotlin-home /path/to/kotlinc LibboxAPI -v
```

Release tests also cover missing/invalid signing inputs in the early workflow
preflight, the exact colon-delimited public fingerprint, malformed formats, version
regression, AGP metadata selection, independent certificate mismatch, v1-only
rejection, secret scopes, log redaction and failure cleanup. On Linux, the actual
`build.sh` is launched with the template's job/build-step environment, resolving
secret references to synthetic sentinels. A Go-command shim inspects its own and
ancestor build-process `/proc` environments, then stops before source preparation.
It proves those processes did not receive signing variables; it does not prove
same-user sandboxing or execute a real Go/Gradle build. To run real signing
on the small AOSP fixture described above, using **only a disposable TEST key**:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/android/test_release.py \
  --apksigner-jar /path/to/build-tools-37/lib/apksigner.jar \
  --aosp-apk /path/to/golden-aligned-v1v2v3-out.apk \
  --java-home /path/to/jdk-17 -v
```

This checks both tool and AOSP fixture hashes, strips the fixture signatures,
rejects the unsigned APK, generates a one-day **PKCS12 TEST key** inside a temporary
directory (matching store/key passwords as required by JDK PKCS12), exercises real
preflight with its base64 bytes and colon-separated public certificate, signs
with the production password-argument helper, independently derives its certificate
digest, and rejects wrong-cert/tampered APKs. The TEST
key and all outputs are removed even on failure. It is **not** an end-to-end
Android/libbox/AGP/R8 build, a release-key setup or a phone upgrade test.

The tests show RED on pristine sources and GREEN after the complete patch layer,
then reject double apply, wrong refs, local properties and unrelated same-file
edits. Synthetic ZIP fixtures exercise identity/version/ABI/ELF/certificate
rejection; **they are not compiled APKs**. Static source checks confirm update
gates, callback propagation, tags and signing/branding contracts. Kotlin/Gradle
compilation and sing-box APK signature validation occur in the hosted run;
the report fixture separately exercises the real pinned verifier's output format.
The external workflow contract checker additionally uses PyYAML; `actionlint`
provides the Actions schema/expression checks and ShellCheck checks shell blocks.

To upgrade: choose a coherent core/app gitlink pair, update the manifest and
workflow template together, rebase each patch explicitly, recheck public
toolchain/action metadata, update versionName/versionCode, run the suite and
linting, and render from the newly committed tooling SHA. Patch conflicts fail;
never skip a patch, use `--3way` automatically, or silently follow a moving branch.

The Galaxy Fold6 is an **arm64-v8a candidate**, not a remotely inspected device.
Before installation record `adb shell getprop ro.product.cpu.abilist`,
`adb shell getprop ro.build.version.release` and
`adb shell getprop ro.build.version.sdk`; require `arm64-v8a`.
On-device acceptance must cover VPN permission/revocation, provider coexistence,
updater inactivity, socket-protect failure propagation, Tailscale enrollment,
Wi-Fi/mobile transitions and IPv6 Shadowsocks reachability, dual-stack/DNS,
mainland/LAN direct routing and proxy-failure **no-direct-fallback** behavior.
Also test Android always-on/lockdown semantics and OEM battery restrictions.
No build alone validates those network requirements; real credentials and
phone/Tailscale operations remain outside this preparation job.
