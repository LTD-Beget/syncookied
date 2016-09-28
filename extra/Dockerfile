FROM ubuntu:trusty

RUN apt-get update && apt-get -y install build-essential curl musl-tools musl-dev git flex bison
ADD musl-build.sh /usr/src/
RUN chmod a+x /usr/src/musl-build.sh

VOLUME /usr/src/syncookied
WORKDIR /usr/src/syncookied

ENTRYPOINT [ "/usr/src/musl-build.sh" ]
