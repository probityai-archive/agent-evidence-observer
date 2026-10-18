#!/bin/bash
set -u
S=https://snapshot.debian.org/archive/debian/20261005T000000Z/pool/main
for u in $S/s/strace/strace_6.13%2Bds-1_amd64.deb $S/libu/libunwind/libunwind8_1.8.1-0.1_amd64.deb; do
  curl -fsSL --retry 3 -o /tmp/probe.deb "$u" && echo "$(sha256sum /tmp/probe.deb | cut -c1-64) $u" || echo "FETCH_FAILED $u"
done
curl -fsSL -o /tmp/probe.deb http://deb.debian.org/debian/pool/main/s/strace/strace_6.13%2bds-1_amd64.deb && echo "deb.debian.org $(sha256sum /tmp/probe.deb | cut -c1-64)"
rm -f /tmp/probe.deb
