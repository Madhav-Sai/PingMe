# PingMe container image.
#   docker build -t pingme .
#   docker run --rm --network host pingme 192.168.1.0/24
#   docker run -d --network host -v pingme-data:/data pingme 192.168.1.0/24 --serve 0.0.0.0:9109 --watch 60
# --network host lets PingMe see the LAN (ARP/ND evidence, MAC vendors, IPv6 discovery).
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends fping iputils-ping iproute2 traceroute \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data pingme \
 && mkdir -p /data /work && chown pingme /data /work

COPY pingme.py /usr/local/bin/pingme
RUN chmod 0755 /usr/local/bin/pingme

ENV PINGME_DATA_DIR=/data PYTHONUNBUFFERED=1
VOLUME /data
WORKDIR /work
USER pingme
EXPOSE 9109
ENTRYPOINT ["pingme"]
CMD ["--help"]
