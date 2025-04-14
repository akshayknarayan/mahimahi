# Mahimahi

A web performance measurement toolkit

## Install

### Requirements

On Ubuntu (at least), you need the following packages to install mahimahi:
 * make
 * autoconf
 * libtool
 * iproute2
 * iptables
 * dnsmasq
 * apache2
 * apache2-dev
 * protobuf-compiler
 * pkg-config
 * libssl-dev
 * libxcb-present-dev
 * libpangomm-2.48-dev

### Install

Once all dependencies are met, you can install mahimahi by running:
 * `./autogen.sh`
 * `./configure`
 * `make`
 * `sudo make install`

Note: mahimahi will conflict with tailscale if it is installed, because tailscale uses the same CG-NAT address space of `100.64.0.0`. This fork includes the configure flag `--enable-altaddr=yes`, which will use the `10.0.0.0` address space instead. To use:

```
./configure --enable-altaddr=yes
```

# Experimental features in this fork

1. mm-link reports the BDP in bytes and packets on startup when a delayshell is
   nested inside
2. Dropping packet queues accept limits in BDP for convenience
3. Run mm-link --cbr [INT][K|M] to automatically generate and use a constant
   bit-rate trace file for any integer value of Kbps or Mbps
4. Record src and dst port of packets for distinguishing flows in plotting
5. Improved plotting script mm-graph (more customizable and able to show
   throughput for individual flows)
5. (Coming soon) live graphing over ssh (via a browser app)
