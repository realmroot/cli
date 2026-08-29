#!/usr/bin/env bash

set -euo pipefail

dist_dir="${1:-dist}"
checksums_file="$dist_dir/checksums.txt"

if [[ ! -f "$checksums_file" ]]; then
    echo "missing release checksums: $checksums_file" >&2
    exit 1
fi

version="$(
    find "$dist_dir" -maxdepth 1 -type f -name 'realmroot_*_darwin_amd64.tar.gz' -print |
        sed -n 's|.*/realmroot_\(.*\)_darwin_amd64\.tar\.gz$|\1|p'
)"
if [[ -z "$version" || "$version" == *$'\n'* ]]; then
    echo "could not determine one release version from $dist_dir" >&2
    exit 1
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
        return
    fi
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
        return
    fi
    echo "sha256sum or shasum is required" >&2
    exit 1
}

verify_archive() {
    local os="$1"
    local arch="$2"
    local extension="tar.gz"
    local binary="realmroot"
    if [[ "$os" == "windows" ]]; then
        extension="zip"
        binary="realmroot.exe"
    fi

    local filename="realmroot_${version}_${os}_${arch}.${extension}"
    local pathname="$dist_dir/$filename"
    if [[ ! -f "$pathname" ]]; then
        echo "missing release archive: $filename" >&2
        return 1
    fi

    local checksum_lines
    checksum_lines="$(awk -v filename="$filename" '$2 == filename { print $1 }' "$checksums_file")"
    if [[ -z "$checksum_lines" || "$checksum_lines" == *$'\n'* || ! "$checksum_lines" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "expected one SHA-256 checksum for $filename" >&2
        return 1
    fi

    local actual_checksum
    actual_checksum="$(sha256_file "$pathname")"
    if [[ "${actual_checksum,,}" != "${checksum_lines,,}" ]]; then
        echo "checksum mismatch for $filename" >&2
        return 1
    fi

    if [[ "$extension" == "zip" ]]; then
        unzip -Z1 "$pathname" | grep -Fxq "$binary"
    else
        tar -tzf "$pathname" | grep -Fxq "$binary"
    fi
    echo "verified $filename"
}

for os in darwin linux windows; do
    for arch in amd64 arm64; do
        verify_archive "$os" "$arch"
    done
done
