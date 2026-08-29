#!/usr/bin/env bash

set -euo pipefail

build_dir="${1:-build}"
targets=(
    darwin_amd64
    darwin_arm64
    linux_amd64
    linux_arm64
    windows_amd64
    windows_arm64
)

actual_count="$(find "$build_dir" -maxdepth 1 -type f -name 'realmroot_*' | wc -l | tr -d ' ')"
if [[ "$actual_count" != "${#targets[@]}" ]]; then
    echo "expected ${#targets[@]} matrix binaries, found $actual_count" >&2
    exit 1
fi

for target in "${targets[@]}"; do
    os="${target%_*}"
    arch="${target#*_}"
    suffix=''
    if [[ "$os" == windows ]]; then
        suffix='.exe'
    fi

    binary="$build_dir/realmroot_${target}${suffix}"
    if [[ ! -f "$binary" ]]; then
        echo "missing matrix binary: $binary" >&2
        exit 1
    fi

    metadata="$(go version -m "$binary")"
    grep -Fq $'\tbuild\tGOOS='"$os" <<<"$metadata"
    grep -Fq $'\tbuild\tGOARCH='"$arch" <<<"$metadata"
    echo "verified realmroot_${target}${suffix}"
done
