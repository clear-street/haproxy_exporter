ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

COPY haproxy_exporter /bin/haproxy_exporter

EXPOSE      9101
USER        nobody
ENTRYPOINT  [ "/bin/haproxy_exporter" ]
