# OT-Guard runs the same image for every role (engine, dashboard, attacker);
# docker-compose picks the command. lxml ships manylinux wheels, so no build
# toolchain is needed on python:3.12-slim.
FROM python:3.14-slim

# Drop privileges: the engine only ever reads the watched files and appends to
# the ledger under /data, so it has no reason to run as root.
RUN useradd --create-home --uid 10001 otguard

# Stream logs immediately instead of block-buffering stdout under Docker.
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=otguard:otguard . .
RUN pip install --no-cache-dir ".[dashboard]"

# /data holds the demo workspace: otguard.toml, the watched L5X, the signed
# baselines and the append-only ledger. Create it owned by the unprivileged
# user *before* declaring the volume, so a fresh named volume inherits that
# ownership (Docker seeds an empty volume from the image directory) and the
# engine can write as uid 10001. docker-compose mounts a named volume here so
# approvals and the ledger survive restarts.
RUN mkdir -p /data && chown otguard:otguard /data
ENV OTGUARD_CONFIG=/data/otguard.toml
VOLUME ["/data"]

USER otguard

ENTRYPOINT ["otguard"]
CMD ["--help"]
