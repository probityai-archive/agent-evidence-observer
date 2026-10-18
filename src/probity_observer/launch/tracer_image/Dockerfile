# The observer's tracer image: python3 and strace for the tracer that attaches to an OpenShell
# sandbox from outside it, and for the exec-identity resolver. The agent image supplies neither.
# Every input is pinned by digest (the base image, and both Debian packages from one
# snapshot.debian.org timestamp), and the build rewrites file times to SOURCE_DATE_EPOCH, so the
# image digest is a function of this file alone (backend_openshell.tracer_image checks it).
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ADD --checksum=sha256:db21a86dd05c93413f0ef36282a9c64d32410d240f332273a53be1408bec1f62 \
    https://snapshot.debian.org/archive/debian/20261005T000000Z/pool/main/libu/libunwind/libunwind8_1.8.1-0.1_amd64.deb \
    /tmp/libunwind8.deb
ADD --checksum=sha256:cae290b67cf835350a2cde58ca332256fba475784b3e02a9a8677d73eaf47511 \
    https://snapshot.debian.org/archive/debian/20261005T000000Z/pool/main/s/strace/strace_6.13%2Bds-1_amd64.deb \
    /tmp/strace.deb
RUN dpkg -i /tmp/libunwind8.deb /tmp/strace.deb \
    && rm -f /tmp/libunwind8.deb /tmp/strace.deb /var/log/dpkg.log /var/log/alternatives.log \
        /var/cache/ldconfig/aux-cache /var/lib/dpkg/status-old \
    && rm -rf /var/log/apt
