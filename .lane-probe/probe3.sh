#!/bin/bash
set -u
D=src/probity_observer/launch/tracer_image
T=$(mktemp -d)
for i in 1 2; do
  docker buildx build --no-cache -q --build-arg SOURCE_DATE_EPOCH=0 \
    --output type=oci,dest=$T/t$i.tar,rewrite-timestamp=true $D > $T/b$i.txt 2>&1; echo "build$i rc=$? $(tail -1 $T/b$i.txt)"
  mkdir $T/x$i; tar -xf $T/t$i.tar -C $T/x$i; echo "index $(sha256sum $T/x$i/index.json | cut -c1-64)"; cat $T/x$i/index.json; echo
  docker load -i $T/t$i.tar | tail -1
done
docker images --digests | grep -i none | head -5
rm -rf $T
