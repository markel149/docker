FROM alpine:3.8

RUN apk update
RUN apk add --no-cache openjdk8-jre su-exec

ENV VERSION 7.6.1
ENV DOWNLOAD https://artifacts.elastic.co/downloads/kibana
ENV FILE "kibana-${VERSION}-linux-x86_64.tar.gz"
ENV URL "${DOWNLOAD}/"${FILE}""

RUN addgroup --gid 1000 kibana && \
  adduser -u 1000 -G kibana \
  -h /usr/share/kibana -H -D \
  kibana

RUN apk add --no-cache libzmq bash
RUN apk add --no-cache nodejs npm
RUN apk add --no-cache -t .build-deps wget ca-certificates gnupg openssl
RUN rm -rf /usr/share/kibana/node

RUN cd /tmp/ \
   && wget "$URL" \
   && tar -xzf "$FILE" \
   && mv "kibana-$VERSION-linux-x86_64" /usr/share/kibana \
   && chown --recursive kibana:root /usr/share/kibana \
   && chown -R kibana:root /usr/share/kibana \
   && chown --recursive kibana:kibana /usr/share/kibana/bin/kibana \
   && chown -R kibana:kibana /usr/share/kibana/bin/kibana \
   && chmod -R g=u /usr/share/kibana/bin/kibana \
   && chmod -R +x /usr/share/kibana/bin/kibana \
   && chmod -R +w /usr/share/kibana/data \
   && find /usr/share/kibana/bin/kibana -type d -exec chmod g+s {} \; \
   #&& ln -s /usr/share/kibana /opt/kibana \
   && rm -rf /tmp/* \
   && apk del --purge .build-deps \
   && bundled='NODE="${DIR}/node/bin/node"' \
   && alpine_node='NODE="/usr/local/bin/node"' \
   && sed -i "s|$bundled|$alpine_node|g" /usr/share/kibana/bin/kibana-plugin \
   && sed -i "s|$bundled|$alpine_node|g" /usr/share/kibana/bin/kibana \
   && rm -rf /usr/share/kibana/node/bin/node 

RUN apk add --no-cache libc6-compat

#RUN ln -s /lib/libc.musl-x86_64.so.1 /lib/ld-linux-x86-64.so.2

ENV PATH /usr/share/kibana:/sbin:$PATH
ENV LS_SETTINGS_DIR /usr/share/kibana/config
ENV LANG='en_US.UTF-8' LC_ALL='en_US.UTF-8'

USER kibana

EXPOSE 5601

ENTRYPOINT ["/usr/share/kibana/bin/kibana"]

CMD ["--path.settings", "/usr/share/kibana/config/"]