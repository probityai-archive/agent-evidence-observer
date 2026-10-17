# A pinned Python base plus bubblewrap, to run the brokered workload launch with OpenShell's
# seccomp block list inside a container on hosts that have no bwrap of their own.
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN apt-get update \
    && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*
