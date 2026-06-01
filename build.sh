#!/bin/sh
set -eu

VERSION="${VERSION:-snapshot}"
DIST_DIR="${DIST_DIR:-dist}"
MAIN_PACKAGE="./cmd/agent"
BINARY_NAME="agent"

TARGETS="
darwin amd64
darwin arm64
freebsd 386
freebsd amd64
freebsd arm
freebsd arm64
linux 386
linux amd64
linux arm
linux arm64
linux loong64
linux mips
linux mipsle
linux riscv64
linux s390x
windows 386
windows amd64
windows arm64
"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

need_cmd go
need_cmd zip
need_cmd sha256sum

MODULE_PATH="${MODULE_PATH:-$(go list -m)}"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "$TARGETS" | while read -r goos goarch; do
    if [ -z "${goos:-}" ]; then
        continue
    fi

    asset="agent_${goos}_${goarch}"
    workdir="$DIST_DIR/$asset"
    binary="$BINARY_NAME"
    if [ "$goos" = "windows" ]; then
        binary="$BINARY_NAME.exe"
    fi

    mkdir -p "$workdir"
    echo "building $asset"

    env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOMIPS=softfloat \
        go build \
        -trimpath \
        -ldflags "-s -w -X ${MODULE_PATH}/pkg/monitor.Version=${VERSION} -X main.arch=${goarch}" \
        -o "$workdir/$binary" \
        "$MAIN_PACKAGE"

    (
        cd "$workdir"
        zip -q -9 -r "../$asset.zip" "$binary"
    )
done

(
    cd "$DIST_DIR"
    sha256sum ./*.zip > checksums.txt
)

echo "build artifacts are ready in $DIST_DIR"
