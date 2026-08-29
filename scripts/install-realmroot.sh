#!/bin/sh

set -e
set -u

requested_version="${1:-${REALMROOT_VERSION:-stable}}"
case "$requested_version" in
    stable)
        latest_url="$(curl -fsSLo /dev/null -w '%{url_effective}' https://github.com/realmroot/cli/releases/latest)"
        version="${latest_url##*/}"
        version="${version#v}"
        ;;
    v*) version="${requested_version#v}" ;;
    *) version="$requested_version" ;;
esac

case "$version" in
    '' | *[!0-9A-Za-z.+-]*)
        echo "invalid Realmroot version: $version" >&2
        exit 1
        ;;
esac

case "$(uname -s)" in
    Darwin) os="darwin" ;;
    Linux) os="linux" ;;
    *)
        echo "unsupported operating system: $(uname -s)" >&2
        exit 1
        ;;
esac

case "$(uname -m)" in
    x86_64 | amd64) arch="amd64" ;;
    arm64 | aarch64) arch="arm64" ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

filename="realmroot_${version}_${os}_${arch}.tar.gz"
release_url="https://github.com/realmroot/cli/releases/download/v${version}"
tmp_dir="$(mktemp -d -t realmroot-install.XXXXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

curl -fsSL "$release_url/$filename" -o "$tmp_dir/$filename"
curl -fsSL "$release_url/checksums.txt" -o "$tmp_dir/checksums.txt"

if ! expected_checksum="$(
    awk -v filename="$filename" '
        $2 == filename { count++; checksum = $1 }
        END {
            if (count != 1 || checksum !~ /^[0-9a-fA-F]{64}$/) exit 1
            print tolower(checksum)
        }
    ' "$tmp_dir/checksums.txt"
)"; then
    echo "expected one SHA-256 checksum for $filename" >&2
    exit 1
fi

if command -v sha256sum > /dev/null 2>&1; then
    actual_checksum="$(sha256sum "$tmp_dir/$filename" | awk '{ print $1 }')"
elif command -v shasum > /dev/null 2>&1; then
    actual_checksum="$(shasum -a 256 "$tmp_dir/$filename" | awk '{ print $1 }')"
else
    echo "SHA-256 verification requires sha256sum or shasum" >&2
    exit 1
fi

if test "$actual_checksum" != "$expected_checksum"; then
    echo "checksum mismatch for $filename" >&2
    exit 1
fi

tar -xzf "$tmp_dir/$filename" -C "$tmp_dir" realmroot

version_dir="$HOME/.local/opt/realmroot-v$version"
bin_dir="$version_dir/bin"
mkdir -p "$bin_dir" "$HOME/.local/bin" "$HOME/.config/envman"
mv "$tmp_dir/realmroot" "$bin_dir/realmroot"
chmod a+x "$bin_dir/realmroot"
ln -sfn "$bin_dir/realmroot" "$HOME/.local/bin/realmroot"

path_line='export PATH="$HOME/.local/bin:$PATH"'
path_file="$HOME/.config/envman/PATH.env"
touch "$path_file"
if ! grep -Fqx "$path_line" "$path_file"; then
    echo "$path_line" >> "$path_file"
fi

echo "Installed Realmroot v$version at $HOME/.local/bin/realmroot"
echo "Open a new shell or run: source ~/.config/envman/PATH.env"
