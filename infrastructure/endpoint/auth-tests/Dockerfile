# Private journal and SSH services for native authentication collection tests.
# The runtime uses its own PID/network namespaces and bounded writable tmpfs.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
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
