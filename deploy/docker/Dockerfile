FROM    127.0.0.1:5000/homed-service:latest
ARG     TARGETARCH
RUN     mkdir /etc/homed
RUN     ln -s /data/homed-matter.conf /etc/homed/homed-matter.conf
RUN     ln -s /data/homed.log /var/log/homed.log
COPY    homed-matter-$TARGETARCH /usr/bin/homed-matter
CMD     ["/usr/bin/homed-matter"]
