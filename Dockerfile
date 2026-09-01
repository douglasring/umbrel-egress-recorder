# TODO(before publishing an image others run): pin this base by digest.
#
#   docker pull debian:12-slim
#   docker inspect --format='{{index .RepoDigests 0}}' debian:12-slim
#   # then replace the FROM line below with:  FROM debian:12-slim@sha256:<digest>
#
# A mutable base tag under a container that holds NET_RAW in the host network namespace
# is the highest-leverage compromise path in this design. The plain tag is used here so
# the build works for anyone cloning the repo; pin it deliberately before release.
FROM debian:12-slim AS base

# tcpdump is the only runtime dependency beyond the Python standard library.
#
# Install the full `python3` package, not `python3-minimal`: the latter does not provide
# the /usr/bin/python3 entry point this image's ENTRYPOINT depends on, and the sqlite3
# extension module lives in the stdlib package. Do NOT "slim" this back down without
# running the smoke test - a missing interpreter makes the container exit instantly,
# which looks identical to a healthy start until you check the logs.
#
# Note there is no bare `apt-get purge --auto-remove` here. With no package arguments it
# can remove packages this image needs.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends tcpdump python3; \
    rm -rf /var/lib/apt/lists/*; \
    # Nothing that could move data off the node stays in the image.
    rm -f /usr/bin/wget /usr/bin/curl; \
    # Debian's tcpdump drops privileges at startup and cannot be told not to, so the
    # container needs CAP_SETUID/CAP_SETGID and the target account must exist. We use
    # -Z nobody (present in the base image); the tcpdump account is kept so an operator
    # who overrides the flags is not stranded.
    id tcpdump >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin tcpdump; \
    id nobody >/dev/null 2>&1; \
    mkdir -p /data; \
    # Fail the BUILD if the runtime prerequisites are missing, rather than at container
    # start where the only symptom is an exited container.
    python3 -c "import sqlite3, struct, ipaddress; print('python ok', sqlite3.sqlite_version)"; \
    tcpdump --version

WORKDIR /app
COPY recorder/ /app/recorder/

# Thin wrappers so the documented `docker exec umbrel-egress-recorder lookup <ip>` works.
RUN set -eux; \
    for cmd in lookup report status recent healthcheck; do \
      printf '#!/bin/sh\nexec python3 -m recorder %s "$@"\n' "$cmd" > /usr/local/bin/$cmd; \
      chmod 0755 /usr/local/bin/$cmd; \
    done

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/egress.db \
    HISTORY_MINUTES=1440 \
    MAX_DB_MB=64 \
    CAPSTAT_INTERVAL_SECONDS=10

VOLUME ["/data"]

# Catches a broken image at build time rather than at container start, where the only
# symptom is an exited container.
#
# `status` deliberately exits non-zero when there is no capture session (the healthcheck
# relies on that), so its exit code is not an error here - only a crash would be. The
# grep is what actually asserts the CLI ran.
RUN set -eux; \
    python3 -c "import recorder.pcap, recorder.store, recorder.capture, recorder.cli"; \
    DB_PATH=/tmp/selftest.db python3 -m recorder status 2>&1 \
      | grep -q "umbrel-egress-recorder status"; \
    DB_PATH=/tmp/selftest.db lookup 203.0.113.42 | grep -q "NO MATCH"; \
    rm -f /tmp/selftest.db*

# Runs as root because Docker sets no ambient capabilities: a non-root `user:` would get
# CapPrm=0 and AF_PACKET would fail with EPERM. See README "Capabilities".
ENTRYPOINT ["python3", "-m", "recorder"]
CMD ["capture"]
