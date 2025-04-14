FROM ubuntu:24.04

RUN apt update -y && apt install -y make autoconf libtool apache2 apache2-dev protobuf-compiler pkg-config libssl-dev libxcb-present-dev libpangomm-2.48-dev iptables iproute2 dnsmasq

ADD . /mahimahi

WORKDIR /mahimahi
RUN autoreconf -i && ./configure && make && make install
