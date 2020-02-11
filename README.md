# ceph-walkley

CephFS is fantastic, but without a VPN it's not safe to be routed over the
internet, and it lacks client support on many platforms.
The [Linux Kernel Library](https://github.com/lkl/linux/) allows for the linux
kernel to be built as a cross-platform user-space library and integrated into a
regular Android, Windows, macOS, etc. application.
This project combines CephFS, LKL and wireguard, and sprinkles some io-uring on
top.

## License

This project is released under the [GPLv2](COPYING).
