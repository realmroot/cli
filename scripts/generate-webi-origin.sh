#!/bin/sh

set -e
set -u

if test "$#" -ne 2; then
    echo "usage: $0 <version> <output-directory>" >&2
    exit 1
fi

version="${1#v}"
output_dir="$2"

case "$version" in
    '' | *[!0-9A-Za-z.+-]*)
        echo "invalid Realmroot version: $version" >&2
        exit 1
        ;;
esac

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(dirname "$script_dir")"
source_installer="$script_dir/install-realmroot.sh"
webi_releases="$repo_dir/packaging/webi/realmroot/releases.conf"
output="$output_dir/realmroot@$version"

if ! grep -Fqx 'github_releases = realmroot/cli' "$webi_releases"; then
    echo "unexpected Webi release source in $webi_releases" >&2
    exit 1
fi

if test "$(grep -Fxc "pinned_version=''" "$source_installer")" -ne 1; then
    echo "expected one version placeholder in $source_installer" >&2
    exit 1
fi

mkdir -p "$output_dir"
sed "s/^pinned_version=''$/pinned_version='$version'/" "$source_installer" > "$output"
chmod a+x "$output"

echo "Generated $output from packaging/webi/realmroot and scripts/install-realmroot.sh"
