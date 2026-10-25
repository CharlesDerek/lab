# Debian 13 acceptance for the private journal, SSH, PAM and sudo fixtures.
# The runtime uses its own PID/network namespaces and bounded writable tmpfs.
FROM debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 systemd openssh-server openssh-client sudo ca-certificates \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
    && useradd --uid 60000 --home-dir /fixture/home --shell /bin/sh fixture \
    && usermod --password '*' fixture \
    && systemd-machine-id-setup \
    && mkdir -p /etc/systemd/journald.conf.d \
    && printf '%s\n' '[Journal]' 'Storage=volatile' 'RuntimeMaxUse=32M' 'RuntimeKeepFree=8M' \
       'ReadKMsg=no' 'Audit=' 'ForwardToSyslog=no' 'ForwardToKMsg=no' 'ForwardToConsole=no' \
       > /etc/systemd/journald.conf.d/fixture.conf
