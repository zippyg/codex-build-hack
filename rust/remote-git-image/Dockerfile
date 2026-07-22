FROM rust:1.92-bookworm@sha256:6f4766a622f58f6c7d2d75d424caf0505ba1135a09baed69c9c27a1bebe0358c AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release \
    --package promptectomy-egress-proxy \
    --package promptectomy-remote-git-runner \
    --package promptectomy-ssh-agent-relay \
    && strip target/release/promptectomy-egress-proxy \
    && strip target/release/promptectomy-remote-git-runner \
    && strip target/release/promptectomy-ssh-connect \
    && strip target/release/promptectomy-ssh-agent-relay

FROM debian:bookworm-slim@sha256:9b67294679b30e5d6ab257b40594feeb4a4b81f7fcf4131f4decf0d6a212a9b0

COPY remote-git-image/os-packages.lock /usr/share/promptectomy/os-packages.lock
RUN printf '%s\n' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260721T000000Z bookworm main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260721T000000Z bookworm-updates main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260721T000000Z bookworm-security main' \
        > /etc/apt/sources.list \
    && unlink /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        git=1:2.39.5-0+deb12u3 \
        openssh-client=1:9.2p1-2+deb12u10 \
    && dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort > /tmp/os-packages.actual \
    && cmp /usr/share/promptectomy/os-packages.lock /tmp/os-packages.actual \
    && unlink /tmp/os-packages.actual \
    && apt-get clean \
    && rm -r -- /var/lib/apt/lists \
    && mkdir -p /work/input /work/output /work/run /work/relay \
    && chmod 0555 /work /work/input /work/output /work/run /work/relay

COPY --from=build --chown=0:0 /src/target/release/promptectomy-egress-proxy /usr/local/bin/promptectomy-egress-proxy
COPY --from=build --chown=0:0 /src/target/release/promptectomy-remote-git-runner /usr/local/bin/promptectomy-remote-git-runner
COPY --from=build --chown=0:0 /src/target/release/promptectomy-ssh-connect /usr/local/bin/promptectomy-ssh-connect
COPY --from=build --chown=0:0 /src/target/release/promptectomy-ssh-agent-relay /usr/local/bin/promptectomy-ssh-agent-relay
RUN useradd --uid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin promptectomy \
    && chmod 0555 /usr/local/bin/promptectomy-egress-proxy /usr/local/bin/promptectomy-remote-git-runner /usr/local/bin/promptectomy-ssh-connect /usr/local/bin/promptectomy-ssh-agent-relay

LABEL dev.promptectomy.remote-git.protocol="phase4-remote-git-2"

USER 65532:65532
WORKDIR /work
