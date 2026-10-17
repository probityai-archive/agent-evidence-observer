# Test agent image for the launcher: a pinned Python base plus the tracer the
# launcher needs inside the container (strace 6.6 or later; setpriv ships with
# util-linux in the base image).
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN apt-get update \
    && apt-get install -y --no-install-recommends strace \
    && rm -rf /var/lib/apt/lists/*
