#!/bin/sh
set -eu

REPO="${NZ_AGENT_REPO:-dagve11/agent}"
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

install_agent() {
    detect_target
    need_cmd unzip

    asset="agent_${os}_${os_arch}.zip"
    url="https://github.com/${REPO}/releases/latest/download/${asset}"
    tmp_dir="$(mktemp -d)"

    if command -v curl >/dev/null 2>&1; then
        curl --max-time 60 -fsSL "$url" -o "${tmp_dir}/${asset}"
    elif command -v wget >/dev/null 2>&1; then
        wget --timeout=60 -qO "${tmp_dir}/${asset}" "$url"
    else
        err "curl or wget is required"
        exit 1
    fi

    unzip -qo "${tmp_dir}/${asset}" -d "$tmp_dir"
    if [ ! -f "${tmp_dir}/agent" ]; then
        err "agent was not found in release asset."
        exit 1
    fi

    run_as_root mkdir -p "$AGENT_PATH"
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
