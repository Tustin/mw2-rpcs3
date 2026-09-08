FROM alpine:3.22
RUN apk add --no-cache dnsmasq
COPY dnsmasq.conf /etc/dnsmasq.conf.template
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
