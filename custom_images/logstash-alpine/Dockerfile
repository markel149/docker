FROM alpine:3.10

RUN apk update
RUN apk add --no-cache openjdk8-jre su-exec

ENV VERSION 7.6.1
ENV DOWNLOAD https://artifacts.elastic.co/downloads/logstash
ENV FILE "logstash-${VERSION}.tar.gz"
ENV URL "${DOWNLOAD}/"${FILE}""

RUN addgroup --gid 1000 logstash && \
  adduser -u 1000 -G logstash \
  -h /usr/share/logstash -H -D \
  logstash

RUN apk add --no-cache libzmq bash
RUN apk add --no-cache -t .build-deps wget ca-certificates gnupg openssl
RUN cd /tmp/ \
   && wget "$URL" \
   && tar -xzf "$FILE" \
   && mv "logstash-$VERSION" /usr/share/logstash \
   && chown --recursive logstash:logstash /usr/share/logstash \
   && chown -R logstash:root /usr/share/logstash \
   && chown --recursive logstash:logstash /usr/share/logstash/bin/logstash \
   && chown -R logstash:root /usr/share/logstash/bin/logstash \
   && chmod -R g=u /usr/share/logstash/bin/logstash \
   && chmod -R +x /usr/share/logstash/bin/logstash \
   && chmod -R +w /usr/share/logstash/data \
   && find /usr/share/logstash/bin/logstash -type d -exec chmod g+s {} \; \
   && ln -s /usr/share/logstash /opt/logstash \
   && rm -rf /tmp/* \
   && apk del --purge .build-deps
RUN apk add --no-cache libc6-compat

ENV PATH /usr/share/logstash:/sbin:$PATH
ENV LS_SETTINGS_DIR /usr/share/logstash/config
ENV LANG='en_US.UTF-8' LC_ALL='en_US.UTF-8'

RUN mkdir /var/log/suricata

USER logstash

#EXPOSE 1620

ENTRYPOINT ["/usr/share/logstash/bin/logstash"]

CMD ["--path.settings", "/usr/share/logstash/config/"]
