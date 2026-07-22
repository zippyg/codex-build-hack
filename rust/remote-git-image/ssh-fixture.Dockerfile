FROM debian:bookworm-slim@sha256:9b67294679b30e5d6ab257b40594feeb4a4b81f7fcf4131f4decf0d6a212a9b0

RUN printf '%s\n' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260721T000000Z bookworm main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260721T000000Z bookworm-updates main' \
        'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260721T000000Z bookworm-security main' \
        > /etc/apt/sources.list \
    && unlink /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --yes --no-install-recommends \
        git=1:2.39.5-0+deb12u3 \
        openssh-server=1:9.2p1-2+deb12u10 \
    && apt-get clean \
    && rm -r -- /var/lib/apt/lists \
    && useradd --uid 1000 --create-home --shell /usr/bin/git-shell git \
    && passwd --delete git \
    && mkdir -p /run/sshd

ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e", "-f", "/fixture/sshd_config"]
