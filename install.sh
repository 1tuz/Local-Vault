#!/bin/sh
set -eu

repo_url=${DOPBASE_REPOSITORY_URL:-https://github.com/1tuz/Local-Vault}
download_base=${DOPBASE_DOWNLOAD_BASE_URL:-${repo_url%/}/releases/download}
version=${DOPBASE_VERSION:-}
install_dir=${DOPBASE_INSTALL_DIR:-"$HOME/.local/bin"}

if [ -z "$version" ]; then
  api_url=$(printf '%s' "$repo_url" | sed 's#^https://github.com/#https://api.github.com/repos/#; s#\.git$##')
  release_json=$(curl -fsSL "$api_url/releases/latest")
  version=$(printf '%s\n' "$release_json" | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([0-9][0-9.]*\)"[,]\{0,1\}$/\1/p' | head -n 1)
fi
case "$version" in
  ''|*[!0-9.]*|.*|*.|*..*) echo "Invalid Dopbase release version: $version" >&2; exit 1 ;;
esac

os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
  Darwin:x86_64) platform=darwin_amd64 ;;
  Darwin:arm64|Darwin:aarch64) platform=darwin_arm64 ;;
  Linux:x86_64|Linux:amd64) platform=linux_amd64 ;;
  Linux:aarch64|Linux:arm64) platform=linux_arm64 ;;
  *) echo "Unsupported platform: $os $arch" >&2; exit 1 ;;
esac

archive="dopbase_${version}_${platform}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
curl -fsSL "$download_base/$version/$archive" -o "$tmp/$archive"
curl -fsSL "$download_base/$version/checksums.txt" -o "$tmp/checksums.txt"
expected=$(awk -v name="$archive" '$2 == name { print $1 }' "$tmp/checksums.txt")
[ "$(printf '%s' "$expected" | wc -w | tr -d ' ')" = 1 ] || { echo "Missing checksum for $archive" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
else
  echo "Install sha256sum or shasum to verify the download" >&2; exit 1
fi
[ "$actual" = "$expected" ] || { echo "Checksum verification failed" >&2; exit 1; }
mkdir -p "$install_dir"
tar -xzf "$tmp/$archive" -C "$tmp" dopbase
install -m 755 "$tmp/dopbase" "$install_dir/dopbase"
printf 'Installed Dopbase %s to %s/dopbase\n' "$version" "$install_dir"
case ":$PATH:" in *":$install_dir:"*) ;; *) printf 'Add %s to PATH to run dopbase.\n' "$install_dir" ;; esac
