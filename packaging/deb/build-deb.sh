#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the Sharza .deb from already-built binaries.
#
#   packaging/deb/build-deb.sh <version> [arch] [bindir] [outdir]
#
# The workflow builds sharzad and sharza-ctl first, then calls this. Keeping
# the packaging step in a script rather than in YAML means a local run and a
# CI run assemble the same artifact from the same inputs, and the control
# metadata is reviewable in the repo.
#
# dpkg-deb, not nfpm: the deb is the only format needed right now, dpkg-deb is
# already on every Debian host and every Ubuntu runner, and it adds no tool to
# trust. nfpm becomes worth it when there is an rpm and an apk to build too.
set -euo pipefail

version="${1:?usage: build-deb.sh <version> [arch] [bindir] [outdir]}"
arch="${2:-amd64}"
bindir="${3:-dist}"
outdir="${4:-dist}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

for bin in sharzad sharza-ctl; do
  if [ ! -x "$bindir/$bin" ]; then
    echo "build-deb.sh: missing $bindir/$bin; build it before packaging" >&2
    exit 1
  fi
done

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

install -Dm755 "$bindir/sharzad"    "$root/usr/bin/sharzad"
install -Dm755 "$bindir/sharza-ctl" "$root/usr/bin/sharza-ctl"
install -Dm644 "$repo/packaging/systemd/sharzad.service"  "$root/usr/lib/systemd/user/sharzad.service"
install -Dm644 "$repo/packaging/systemd/sharzad@.service" "$root/usr/lib/systemd/user/sharzad@.service"
install -Dm644 "$repo/LICENSE" "$root/usr/share/doc/sharza/copyright"

mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: sharza
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: Jonathan Vanherpe <github@freebase.be>
Homepage: https://github.com/jonathanvanherpe/sharza
Description: Multi-protocol P2P client: daemon, CLI and web UI
 Sharza is a Linux-native multi-protocol peer-to-peer client. It speaks
 BitTorrent, eDonkey2000/Kad and Gnutella/Gnutella2 at once, with a
 daemon-first architecture and namespace-based VPN isolation.
 .
 This package contains the supervisor daemon (which also serves the
 embedded web UI), the sharza-ctl client, and systemd user units.
EOF

mkdir -p "$outdir"
deb="$outdir/sharza_${version}_${arch}.deb"
dpkg-deb --root-owner-group --build "$root" "$deb" >/dev/null
echo "$deb"
