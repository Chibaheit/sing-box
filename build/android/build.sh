#!/usr/bin/env bash
set +x +v
set -euo pipefail

if [[ $# != 1 ]]; then
  echo "Usage: build.sh /absolute/path/to/fresh-pinned-core" >&2
  exit 2
fi
tools=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
core=$(cd -- "$1" && pwd)
app="$core/clients/android"
unset LOCAL_PROPERTIES
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
export GOMAXPROCS=2
: "${ANDROID_HOME:?ANDROID_HOME must point to the licensed SDK}"
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/28.0.13004108"
export NDK="$ANDROID_NDK_HOME"
test -f "$ANDROID_HOME/licenses/android-sdk-license"
test -f "$ANDROID_NDK_HOME/source.properties"
test -d "$ANDROID_HOME/platforms/android-37.1"
test -d "$ANDROID_HOME/platforms/android-36"
test -x "$ANDROID_HOME/build-tools/37.0.0/apksigner"
[[ "$(go env GOVERSION)" == go1.26.8 ]] || { echo "Go 1.26.8 required" >&2; exit 1; }
java --version | grep -q '^openjdk 17' || { echo "OpenJDK 17 required" >&2; exit 1; }
python3 "$tools/prepare.py" apply "$core"

cd -- "$core"
# The pinned fork has non-semver build-* tags. A fresh shallow checkout must
# have no tags; the local-only tag supplies ReadTag's exact custom version.
[[ -z "$(git tag --list)" ]] || { echo "Expected tag-free shallow core checkout" >&2; exit 1; }
version_tag=$(PYTHONPATH="$tools" python3 -c \
  'from prepare import MANIFEST; print(MANIFEST["libbox"]["local_version_tag"])')
git tag "$version_tag"
[[ "$(git describe --tags)" == "$version_tag" ]]
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.13
go_path=$(go env GOPATH)
export PATH="$go_path/bin:$PATH"
go run ./cmd/internal/build_libbox -target android -platform android/arm64
mkdir -p "$app/app/libs"
cp -- libbox.aar libbox-legacy.aar "$app/app/libs/"

cd -- "$app"
# Never import signing properties or touch the tracked upstream release key.
# ANDROID_HOME replaces sdk.dir; no local.properties is created.
./gradlew --no-daemon --max-workers=2 \
  --no-configuration-cache --init-script "$tools/runtime.init.gradle" \
  '-Dorg.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=1g -Dfile.encoding=UTF-8' \
  -Pkotlin.compiler.execution.strategy=in-process \
  :app:captureOtherReleaseProvenance
test -s app/build/runtime-provenance/graph.json
python3 "$tools/prepare.py" verify "$core"
