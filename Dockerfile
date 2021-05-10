FROM ubuntu


RUN apt-get clean
RUN apt-get update
RUN apt-get upgrade -y

ENV TZ=Europe/Kiev
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

ENV debian_frontend noninteractive
RUN debian_frontend=noninteractive apt-get install \
    make git cmake clang python3 python3-pip wget ninja-build \
    libtool libtool-bin automake autoconf bison flex curl \
    pkg-config libglib2.0-dev libpixman-1-dev vim gnuplot -y

RUN git clone https://github.com/AFLplusplus/AFLplusplus --branch 3.12c 
RUN cd AFLplusplus && \
        make afl-fuzz afl-showmap afl-tmin afl-gotcpu afl-analyze && \
        cd qemu_mode && CPU_TARGET=aarch64 ./build_qemu_support.sh

RUN ln -s /usr/bin/python3 /usr/bin/python

RUN apt install curl -y
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y 
ENV PATH="${HOME}/.cargo/bin:${PATH}"

ADD bin /fuzz/bin
ADD system /system
ADD samples /fuzz/samples
