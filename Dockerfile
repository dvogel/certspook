FROM debian:12-slim

MAINTAINER Drew Vogel

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y aptitude build-essential git cmake \
                       zlib1g-dev libevent-dev \
                       libelf-dev llvm \
                       clang libc6-dev-i386

RUN mkdir /opt/certspook
WORKDIR /opt/certspook

ENTRYPOINT ["/bin/bash"]
CMD ["-l"]

