#!/bin/bash
set -u
B=python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
docker run --rm --network bridge $B sh -c 'apt-get update -qq >/dev/null 2>&1; apt-get install --no-install-recommends --print-uris -qq strace; echo ---; cat /etc/apt/sources.list.d/* | head; dpkg -l | wc -l'
docker run --rm $B sh -c 'ls -la /usr/local/bin/python3*; python3 -V'
docker buildx version; docker info --format '{{.DriverStatus}} {{index .Driver}}'
