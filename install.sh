#!/bin/sh
set -eu

REPO="${NZ_AGENT_REPO:-dagve11/agent}"
GITEE_REPO="${NZ_GITEE_REPO:-AGZZY11/agent}"
BASE_PATH="${NZ_BASE_PATH:-/opt/agent}"
AGENT_PATH="${BASE_PATH}/agent"
CONFIG_PATH="${AGENT_PATH}/config.yml"

err() {
    printf '%s\n' "$*" >&2
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "missing required command: $1"
        exit 1
    fi
}

geo_check() {
    if [ -n "${CN:-}" ]; then
        return
    fi

    if ! command -v curl >/dev/null 2>&1; then
        return
    fi

    ua="Mozilla/5.0 (X11; Linux x86_64) agent-installer"
    for url in \
        "https://blog.cloudflare.com/cdn-cgi/trace" \
        "https://developers.cloudflare.com/cdn-cgi/trace" \
        "https://1.0.0.1/cdn-cgi/trace"
    do
        text="$(curl -A "$ua" -m 5 -fsSL "$url" 2>/dev/null || true)"
        if printf '%s\n' "$text" | grep -q '^loc=CN$'; then
            CN=true
            export CN
            return
        fi
    done
}

run_as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        err "root permission is required, and sudo is not installed."
        exit 1
    fi
}

detect_target() {
    case "$(uname -m)" in
        amd64|x86_64) os_arch="amd64" ;;
        i386|i686) os_arch="386" ;;
        aarch64|arm64) os_arch="arm64" ;;
        *arm*) os_arch="arm" ;;
        s390x) os_arch="s390x" ;;
        riscv64) os_arch="riscv64" ;;
        mips) os_arch="mips" ;;
        mipsel|mipsle) os_arch="mipsle" ;;
        loongarch64) os_arch="loong64" ;;
        *) err "unsupported architecture: $(uname -m)"; exit 1 ;;
    esac

    case "$(uname)" in
        *Linux*) os="linux" ;;
        *Darwin*) os="darwin" ;;
        *FreeBSD*) os="freebsd" ;;
        *) err "unsupported system: $(uname)"; exit 1 ;;
    esac
}

quote_yaml() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

read_existing_uuid() {
    if [ -n "${NZ_UUID:-}" ] || [ ! -f "$CONFIG_PATH" ]; then
        return
    fi

    uuid="$(sed -n "s/^[[:space:]]*uuid:[[:space:]]*['\"]\\{0,1\\}\\([^'\"]*\\)['\"]\\{0,1\\}[[:space:]]*$/\\1/p" "$CONFIG_PATH" | head -n 1)"
    if [ -n "$uuid" ]; then
        NZ_UUID="$uuid"
        export NZ_UUID
    fi
}

write_config() {
    if [ -z "${NZ_SERVER:-}" ]; then
        err "NZ_SERVER should not be empty"
        exit 1
    fi

    if [ -z "${NZ_CLIENT_SECRET:-}" ]; then
        err "NZ_CLIENT_SECRET should not be empty"
        exit 1
    fi

    tls="${NZ_TLS:-false}"
    if [ "$tls" != "true" ] && [ "$tls" != "false" ]; then
        err "NZ_TLS must be true or false"
        exit 1
    fi

    tmp_config="$(mktemp)"
    {
        printf 'server: %s\n' "$(quote_yaml "$NZ_SERVER")"
        printf 'client_secret: %s\n' "$(quote_yaml "$NZ_CLIENT_SECRET")"
        printf 'tls: %s\n' "$tls"
        if [ -n "${NZ_UUID:-}" ]; then
            printf 'uuid: %s\n' "$(quote_yaml "$NZ_UUID")"
        fi
    } > "$tmp_config"
    run_as_root mv "$tmp_config" "$CONFIG_PATH"
}

add_download_url() {
    candidate="$1"
    if [ -z "$candidate" ]; then
        return
    fi
    case "
$download_urls
" in
        *"
$candidate
"*) return ;;
    esac
    download_urls="${download_urls}
${candidate}"
}

gitee_asset_url() {
    if [ -z "$GITEE_REPO" ]; then
        return
    fi
    if ! command -v curl >/dev/null 2>&1; then
        return
    fi

    tag="$(curl -m 10 -fsSL "https://gitee.com/api/v5/repos/${GITEE_REPO}/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1 || true)"
    if [ -n "$tag" ]; then
        printf 'https://gitee.com/%s/releases/download/%s/%s\n' "$GITEE_REPO" "$tag" "$1"
    fi
}

build_download_urls() {
    asset="$1"
    direct_url="https://github.com/${REPO}/releases/latest/download/${asset}"
    download_urls=""

    if [ -n "${NZ_DOWNLOAD_BASE:-}" ]; then
        add_download_url "$(printf '%s/%s' "$(printf '%s' "$NZ_DOWNLOAD_BASE" | sed 's:/*$::')" "$asset")"
    fi

    geo_check
    if [ "${CN:-}" = "true" ]; then
        add_download_url "$(gitee_asset_url "$asset")"
    fi

    if [ -n "${NZ_GITHUB_PROXY:-}" ]; then
        add_download_url "$(printf '%s/%s' "$(printf '%s' "$NZ_GITHUB_PROXY" | sed 's:/*$::')" "$direct_url")"
    fi

    add_download_url "$direct_url"
}

download_release_asset() {
    asset="$1"
    dest="$2"

    build_download_urls "$asset"

    for url in $download_urls; do
        printf '%s\n' "Downloading $url"
        if command -v curl >/dev/null 2>&1; then
            if curl --connect-timeout 10 --max-time 60 -fL "$url" -o "$dest"; then
                return 0
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget --timeout=60 -qO "$dest" "$url"; then
                return 0
            fi
        else
            err "curl or wget is required"
            exit 1
        fi
        rm -f "$dest"
    done

    err "Download agent release failed. You can set NZ_DOWNLOAD_BASE, NZ_GITHUB_PROXY, or NZ_GITEE_REPO to use a mirror."
    exit 1
}

install_agent() {
    detect_target
    need_cmd unzip

    asset="agent_${os}_${os_arch}.zip"
    tmp_dir="$(mktemp -d)"
    download_release_asset "$asset" "${tmp_dir}/${asset}"

    unzip -qo "${tmp_dir}/${asset}" -d "$tmp_dir"
    if [ ! -f "${tmp_dir}/agent" ]; then
        err "agent was not found in release asset."
        exit 1
    fi

    run_as_root mkdir -p "$AGENT_PATH"
    read_existing_uuid
    if [ -x "${AGENT_PATH}/agent" ]; then
        run_as_root "${AGENT_PATH}/agent" service -c "$CONFIG_PATH" stop >/dev/null 2>&1 || true
        run_as_root "${AGENT_PATH}/agent" service -c "$CONFIG_PATH" uninstall >/dev/null 2>&1 || true
    fi

    run_as_root mv "${tmp_dir}/agent" "${AGENT_PATH}/agent"
    run_as_root chmod +x "${AGENT_PATH}/agent"
    write_config

    run_as_root "${AGENT_PATH}/agent" service -c "$CONFIG_PATH" install
    run_as_root "${AGENT_PATH}/agent" service -c "$CONFIG_PATH" start
    rm -rf "$tmp_dir"

    printf '%s\n' "agent installed and started."
}

uninstall_agent() {
    if [ -x "${AGENT_PATH}/agent" ]; then
        run_as_root "${AGENT_PATH}/agent" service -c "$CONFIG_PATH" stop >/dev/null 2>&1 || true
        run_as_root "${AGENT_PATH}/agent" service -c "$CONFIG_PATH" uninstall >/dev/null 2>&1 || true
    fi
    run_as_root rm -rf "$BASE_PATH"
    printf '%s\n' "agent uninstalled."
}

case "${1:-install}" in
    install) install_agent ;;
    uninstall) uninstall_agent ;;
    *) err "usage: $0 [install|uninstall]"; exit 1 ;;
esac
