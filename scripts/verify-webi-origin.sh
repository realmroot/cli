#!/bin/sh

set -e
set -u

if test "$#" -ne 1; then
    echo "usage: $0 <version>" >&2
    exit 1
fi

version="${1#v}"
script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(dirname "$script_dir")"
committed="$repo_dir/packaging/webi/origin/realmroot@$version"
tmp_dir="$(mktemp -d -t realmroot-webi-origin.XXXXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

"$script_dir/generate-webi-origin.sh" "$version" "$tmp_dir/generated"
cmp "$committed" "$tmp_dir/generated/realmroot@$version"

mkdir -p "$tmp_dir/bin" "$tmp_dir/fixtures"
cat > "$tmp_dir/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
    -s) printf '%s\n' "$TEST_UNAME_OS" ;;
    -m) printf '%s\n' "$TEST_UNAME_ARCH" ;;
    *) exit 1 ;;
esac
EOF
cat > "$tmp_dir/bin/curl" <<'EOF'
#!/bin/sh
output=''
url=''
while test "$#" -gt 0; do
    case "$1" in
        -o) output="$2"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
test -n "$output"
test -n "$url"
cp "$TEST_FIXTURES/${url##*/}" "$output"
EOF
chmod a+x "$tmp_dir/bin/uname" "$tmp_dir/bin/curl"

verify_target() {
    os="$1"
    arch="$2"
    uname_os="$3"
    uname_arch="$4"
    filename="realmroot_${version}_${os}_${arch}.tar.gz"
    target_dir="$tmp_dir/target-$os-$arch"
    home_dir="$tmp_dir/home-$os-$arch"

    mkdir -p "$target_dir" "$home_dir"
    printf '#!/bin/sh\nprintf "realmroot v%s\\n"\n' "$version" > "$target_dir/realmroot"
    chmod a+x "$target_dir/realmroot"
    tar -czf "$tmp_dir/fixtures/$filename" -C "$target_dir" realmroot
    if command -v sha256sum > /dev/null 2>&1; then
        checksum="$(sha256sum "$tmp_dir/fixtures/$filename" | awk '{ print $1 }')"
    else
        checksum="$(shasum -a 256 "$tmp_dir/fixtures/$filename" | awk '{ print $1 }')"
    fi
    printf '%s  %s\n' "$checksum" "$filename" > "$tmp_dir/fixtures/checksums.txt"

    HOME="$home_dir" \
        PATH="$tmp_dir/bin:/usr/bin:/bin" \
        TEST_FIXTURES="$tmp_dir/fixtures" \
        TEST_UNAME_OS="$uname_os" \
        TEST_UNAME_ARCH="$uname_arch" \
        REALMROOT_VERSION=9.9.9 \
        sh "$committed" 8.8.8

    test "$("$home_dir/.local/bin/realmroot")" = "realmroot v$version"
}

verify_target darwin amd64 Darwin x86_64
verify_target darwin arm64 Darwin arm64
verify_target linux amd64 Linux x86_64
verify_target linux arm64 Linux aarch64

corrupt_home="$tmp_dir/home-corrupt"
mkdir -p "$corrupt_home"
printf '%064d  realmroot_%s_linux_amd64.tar.gz\n' 0 "$version" > "$tmp_dir/fixtures/checksums.txt"
if HOME="$corrupt_home" \
    PATH="$tmp_dir/bin:/usr/bin:/bin" \
    TEST_FIXTURES="$tmp_dir/fixtures" \
    TEST_UNAME_OS=Linux \
    TEST_UNAME_ARCH=x86_64 \
    sh "$committed" > "$tmp_dir/corrupt.log" 2>&1; then
    echo "corrupt archive unexpectedly installed" >&2
    exit 1
fi
grep -Fq 'checksum mismatch' "$tmp_dir/corrupt.log"
test ! -e "$corrupt_home/.local/bin/realmroot"

echo "Verified generated Webi origin for Realmroot v$version"
