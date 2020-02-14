# ceph-walkley

CephFS is fantastic, but without a VPN it's not safe to be routed over the
internet, and it lacks client support on many platforms.
The [Linux Kernel Library](https://github.com/lkl/linux/) allows for the linux
kernel to be built as a cross-platform user-space library and integrated into a
regular Android, Windows, macOS, etc. application.
This project combines CephFS, LKL and wireguard, and sprinkles some io-uring on
top.

## Building

To build all components from the top level, run:
```
make
```

The kernel builds with the config at `linux/arch/um/lkl/configs/lkl_defconfig`.
All components can be built against the Android NDK (tested with android-ndk-r21
on x86-64, cross compiling for aarch64).
As a workaround for https://github.com/lkl/linux/issues/475 , GNU ld (GNU
Binutils; openSUSE Leap 15.1) 2.31.1.20180828-lp151.2 can be used instead of GNU
ld (GNU Binutils) 2.27.0.20170315 from the NDK. E.g.
```
arch="aarch64"
ndk_tc="~/android-ndk-r21/toolchains/llvm/prebuilt/linux-x86_64"
suse_cross_ld="/usr/bin/${arch}-suse-linux-ld"

make TARGET="android" \
        AR="${ndk_tc}/bin/${arch}-linux-android-ar" \
        CC="${ndk_tc}/bin/${arch}-linux-android21-clang" \
        HOSTCC=gcc HOSTLD=ld \
        KCFLAGS=-Wno-implicit-fallthrough \
        LD=${suse_cross_ld} \
        NM="${ndk_tc}/bin/${arch}-linux-android${eabi}-nm" \
        OBJDUMP="${ndk_tc}/bin/${arch}-linux-android-objdump" \
        OBJSIZE="${ndk_tc}/bin/${arch}-linux-android-size" \
        OBJCOPY="${ndk_tc}/bin/${arch}-linux-android-objcopy"
```

## Usage

The walkley binary can be run with the following parameters:
```
  -i, --tap-if               tap interface name
  -d, --dhcp                 use DHCP
  -I, --ip                   IPv4 address
  -n, --netmask-len          IPv4 netmask length
  -D, --dst                  IPv4 address to ping after network setup
  -S, --seed                 entropy string to seed /dev/random
  -M, --mnt-dev              device or network target to mount
  -T, --mnt-fs-type          filesystem type to mount
  -O, --mnt-opts             mount options
  -p, --wg-port              wireguard port
  -t, --wg-tun-ip            wireguard tunnel IPv4 address
  -m, --wg-tun-netmask-len   wireguard tunnel netmask length
  -k, --wg-priv-key          wireguard device base64 encoded private key
  -K, --wg-peer-pub-key      wireguard peer base64 encoded public key
  -E, --wg-peer-ep-ip        wireguard peer endpoint IPv4 address
  -P, --wg-peer-ep-port      wireguard peer endpoint port
```

Currently only _tap_ based networking is working. The `--seed` parameter is
provided to avoid stalls due to lack of entropy within the LKL kernel.

Example:
```
  ./walkley -i tap0 \
            -I 192.168.1.2 \
            -n 24 \
            --seed "$(uuidgen -r)" \
            --mnt-dev "10.30.50.1:6789:/" \
            --mnt-fs-type ceph \
            --mnt-opts "name=admin,secret=<CephX key>" \
            --wg-port 42424 \
            --wg-tun-ip 10.30.50.2 \
            --wg-tun-netmask-len 24 \
            --wg-priv-key "<base64 encoded wireguard private key>" \
            --wg-peer-pub-key "<base64 encoded wireguard peer public key>" \
            --wg-peer-ep-ip 192.168.1.1 \
            --wg-peer-ep-port 24242
```

## License

This project is released under the [GPLv2](COPYING).
