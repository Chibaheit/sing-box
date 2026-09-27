# Pinned Chibaheit SFA Android debug trial

This is a small patch layer, not a new Android fork or protocol implementation.
Recommended first trial: fork core `4a39ff496a245e1864cdbe608cab09f5d17df9bc`
and its exact `clients/android` gitlink
`a3668ae6e4bbcb3ceff8461d0cac55d79edf504f`. The app's baseline is **1.14.1,
versionCode 734**, customized as **1.14.1-chibaheit.1**. It is not official
1.14.2. Using the recorded gitlink avoids an unreviewed core/app upgrade, but
does not guarantee API compatibility: the first hosted build exposed the drift
documented below. Neither `testing` nor other PRs are synchronized by this recipe.

Official 1.14.2 would instead require reviewing core
`af6e64c3b69e6132ebaee0e1a3d24e93903f6709` with app
`fc21909df7a3f0fc9435f3866fb6a4960711aa5f` (code 739), rebasing the patch
layer, and repeating compatibility checks. Do not mix that app with this core
or relabel this build as 1.14.2. The separate Android configuration work must
also be checked against this actual binary version before phone use.

## Manual GitHub installation boundary

`custom-android.yml.in` is **non-active build documentation**. No workflow is
installed by this PR. The current credential lacks workflow scope; do not push
workflow files with it, encode them into another active workflow, or dispatch the
existing `build.yml`.

After committing this tooling, render outside every checkout:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/android/render_workflow.py /absolute/outside/repo/delivery
```

Deliver both `custom-android.yml` and `custom-android.patch`. The generated YAML
pins this tooling's full commit SHA, the full core SHA, and the verified app
gitlink; it does not read a moving `dev`/`testing` revision or accept shell inputs.

The user must use **Chibaheit/sing-box > Add file > Create new file** on `testing`
(the default branch), name it exactly **`.github/workflows/custom-android.yml`**,
paste the entire delivered YAML, and manually commit using their GitHub UI
authority. Use the commit message **`Add pinned custom Android workflow [skip ci]`**:
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

Only **after that manual commit**, use Actions > **Custom Android DEBUG trial**
> Run workflow, selecting `testing`. Equivalently, the already-authorized hosted
build can then be dispatched with:

```sh
gh workflow run custom-android.yml --repo Chibaheit/sing-box --ref testing
```

Read back that workflow file before dispatch: it must equal the delivered YAML.
This preparation task does not dispatch, merge, release, or publish an APK.
The new workflow has only `workflow_dispatch`, `contents: read`, no secrets,
no cache mutation/GC, and allowlisted `upload-artifact` output. It does not
execute untrusted pull-request code. Dispatch explicitly accepts Google's
Android SDK/NDK licenses via the named SDK setup step; review those licenses first.

## Build recipe and source evidence

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
  '-Dorg.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=1g -Dfile.encoding=UTF-8' \
  -Pkotlin.compiler.execution.strategy=in-process :app:assembleOtherDebug
```

Use `build.sh`, not these excerpted commands alone: it validates pins, applies
patches, checks the SDK and Go, unsets `LOCAL_PROPERTIES`, and rejects any app
`local.properties` or Play credential file. Supply `ANDROID_HOME`; do not create
`sdk.dir` properties. The patch binds debug signing explicitly to the SDK debug
configuration even if signing properties accidentally exist. The upstream
`app/release.keystore` is never opened, used, copied, or uploaded.

`build_libbox` automatically copies to **`../sing-box-for-android/app/libs`**,
not this repository's submodule. The explicit copy is therefore essential.
Both API-24 main and API-21 legacy AARs are produced by upstream; only the main
AAR is linked into `OtherDebug`. The legacy builder excludes
`with_naive_outbound`. Gradle is limited to two workers/4 GiB heap; Go concurrency
is two. A full build is deliberately not run locally.

The original core builder already includes `with_tailscale`, but **does not
include `with_gvisor`** at this pin. The single-line core build patch adds it:
the pinned `sing-tun` `stack_gvisor.go` requires that tag. All effective tags
are recorded and checked by tests. No Shadowsocks or Tailscale implementation
is duplicated. The shallow, tag-free core checkout gets only the local
`v1.14.1-chibaheit.1` tag for `build_shared.ReadTag`, because fork `build-*` tags
are not semantic versions. This tag is never pushed. No
`update_android_version --ci` or dependency-upgrade command runs.

## Patch audit

1. Core build patch: enable existing gVisor implementation.
2. App identity patch: package **io.chibaheit.sfa**, visible **Chibaheit SFA**
   in every existing app-name locale, custom version, arm64-only split with
   universal disabled, wrapper checksum, build-tools pin, explicit debug signing.
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

`collect.py` requires exactly one APK under `app/build/outputs/apk/other/debug`,
checks package/version/label/debug status with the pinned SDK's `aapt`, verifies
the signature using `apksigner`, and checks **every native .so is arm64-v8a
AArch64 ELF64**, including `libbox.so`. It rejects universal or mislabeled APKs.
Artifacts are the **DEBUG APK**, `SHA256SUMS`, signing-certificate SHA-256,
source manifest (including tooling commit and patch hashes), source patch bundle,
and immutable core/app source archives with licenses. No whole workspace,
build log, key, or credential is uploaded. Source archives contain original
unpatched HEAD blobs; apply the recorded patches to reconstruct the custom source.
Signing material is excluded by name before `git archive`, not removed afterward.

These are reconstructible source pins, not a claim of bit-for-bit reproducibility:
Temurin 17 patch updates, hosted runner image revisions and remote Gradle/Maven
transitive artifacts are not all content-locked. Go modules are checksum-pinned;
the archives include `go.mod`/`go.sum`, Gradle files and wrapper, third-party source
and licenses. Dependency downloads still require the recorded public repositories.
Before any redistribution, retain the sources and required transitive dependency
sources/licenses beyond the artifact's **14-day** retention, review GPL-3.0 and
other license obligations, and provide corresponding source alongside binaries.
This workflow does not authorize or perform distribution.

**The debug key is ephemeral.** A later fresh CI run normally generates a
different key, so `adb install -r` may reject it. Never upload the debug keystore
as an Actions artifact. Back up profiles securely; uninstall/reinstall may be
needed and loses app data/Tailscale identity. Neither package name nor version
alone guarantees upgradeability. The custom app cannot update the official app.

For long-term updates, a separate reviewed release-signing workflow needs a new,
owner-controlled key, durable private backup, and user-provisioned protected
GitHub signing secrets/environment approvals. Do not reuse upstream's key.
Passwords/keys must never enter this PR, logs, or artifacts. Keep the same custom
application ID and certificate and monotonically increase versionCode (next
custom update must exceed 734). This debug-only recipe intentionally does not
request passwords, provision secrets, preserve keys, or claim production signing.

## Validation and upgrade procedure

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
The confirmed parser incompatibility is that build-tools **37.0.0** reports a
single ordinary signer as `V3.0 Signer:` (or `V2 Signer:` / `V1 Signer:`), not
`Signer #1`. This applies to a single SDK debug signing configuration without
rotation; no recipe change or relaxation of package/signature/architecture is
needed. Collection now logs the public verification report before parsing,
requires `Verifies`, exactly one reported signer and one strictly formatted
certificate digest, and rejects extra, rotated or unknown certificate records.
The cryptographic subprocess check and all APK/source/key-exclusion checks remain.

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
Only this verifier was extracted and run with the existing JDK 17; no full SDK,
NDK, Gradle build or local sing-box APK was installed/generated. To recapture:

```sh
java -jar /path/to/apksigner.jar verify --verbose --print-certs \
  /path/to/golden-aligned-v1v2v3-out.apk
```

The regression reproduces the exact CI exception on this real report before the
fix and passes afterward. Negative tests retain rejection of malformed/multiple
signers, mismatched APKs and failing signature commands before artifact creation.
The next real CI collection still requires the reviewed manual tooling-pin update
described above; re-running the old immutable run cannot use this fix.

### Local checks

The script suite needs Python 3.10+ and Git, with an existing local copy of both
source objects; it fetches them into isolated temporary repositories:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/android/test_scripts.py \
  --core-source . --app-source clients/android -v
bash -n build/android/build.sh
shellcheck build/android/build.sh
actionlint /outside/repo/delivery/custom-android.yml
python3 build/android/validate_workflow.py /outside/repo/delivery/custom-android.yml
```

To also run the narrow compiler regression, supply an existing Kotlin 2.4.10
compiler distribution (no SDK, NDK, Gradle or full local build is needed):

```sh
JAVA_HOME=/path/to/jdk-17 PYTHONDONTWRITEBYTECODE=1 \
  python3 build/android/test_scripts.py \
  --core-source . --app-source clients/android \
  --kotlin-home /path/to/kotlinc -v
```

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
