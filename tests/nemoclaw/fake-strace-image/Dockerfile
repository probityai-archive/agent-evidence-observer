# An agent image that ships a fake strace: it prints a real version line, traces nothing and
# exits 0. Under the OpenShell backend the tracer runs from the observer's own tracer image, so
# this binary is never executed and the trace is complete anyway.
FROM python:3.12-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN printf '#!/bin/sh\necho "strace -- version 6.13"\nexit 0\n' > /usr/bin/strace \
    && chmod 0755 /usr/bin/strace
