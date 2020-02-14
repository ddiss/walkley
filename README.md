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
