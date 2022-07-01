// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>

#include <sys/types.h>
#include <dirent.h>

#ifdef __FreeBSD__
#include <sys/types.h>
#endif
#ifdef __MINGW32__
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <lkl.h>
#include <lkl_host.h>
/* FIXME should be using an LKL header for RNDADDENTROPY */
#include <linux/random.h>
#include <wireguard.h>

#include <linux/limits.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

#include "vendor/cl_arg.h"

#ifdef WALKLEY_DEBUG
#define dbg(fmt, ...) \
	fprintf(stderr, "(%s:%d) " fmt, __FILE__, __LINE__, ##__VA_ARGS__);
#else
#define dbg(fmt, ...)
#endif

static u_short in_cksum(const u_short *addr, register int len, u_short csum)
{
	int nleft = len;
	const u_short *w = addr;
	u_short answer;
	int sum = csum;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
		sum += htons(*(u_char *)w << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return answer;
}

static int icmp_txrx(unsigned int dst)
{
	int sock, ret, icmphdr_off;
	size_t pkt_len;
	struct lkl_iphdr *iph;
	struct lkl_icmphdr *icmp;
	struct lkl_sockaddr_in saddr;
	struct lkl_pollfd pfd;
	char buf[32];

	if (dst == INADDR_NONE) {
		return 0;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = LKL_AF_INET;
	saddr.sin_addr.lkl_s_addr = dst;

	sock = lkl_sys_socket(LKL_AF_INET, LKL_SOCK_RAW, LKL_IPPROTO_ICMP);
	if (sock < 0) {
		fprintf(stderr, "socket error (%s)\n", lkl_strerror(sock));
		return -EIO;
	}

	icmp = malloc(sizeof(struct lkl_icmphdr));
	icmp->type = LKL_ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.sequence = 0;
	icmp->un.echo.id = 0;
	icmp->checksum = in_cksum((u_short *)icmp, sizeof(*icmp), 0);

	ret = lkl_sys_sendto(sock, icmp, sizeof(*icmp), 0,
			     (struct lkl_sockaddr *)&saddr,
			     sizeof(saddr));
	free(icmp);
	icmp = NULL;
	if (ret < 0) {
		fprintf(stderr, "sendto error (%s)\n", lkl_strerror(ret));
		return -EIO;
	}

	pfd.fd = sock;
	pfd.events = LKL_POLLIN;
	pfd.revents = 0;

	ret = lkl_sys_poll(&pfd, 1, 1000);
	if (ret < 0) {
		fprintf(stderr, "poll error (%s)\n", lkl_strerror(ret));
		return -EIO;
	}

	ret = lkl_sys_recv(sock, buf, sizeof(buf), LKL_MSG_DONTWAIT);
	if (ret < 0) {
		fprintf(stderr, "recv error (%s)\n", lkl_strerror(ret));
		return -EIO;
	}

	pkt_len = ret;
	if (pkt_len < sizeof(struct lkl_iphdr)) {
		return -EFAULT;
	}

	iph = (struct lkl_iphdr *)buf;
	icmphdr_off = iph->ihl * 4;
	if (pkt_len < icmphdr_off + sizeof(struct lkl_icmphdr)) {
		return -EFAULT;
	}

	icmp = (struct lkl_icmphdr *)(buf + icmphdr_off);
	/* DHCP server may issue an ICMP echo request to a dhcp client */
	if ((icmp->type != LKL_ICMP_ECHOREPLY || icmp->code != 0) &&
	    (icmp->type != LKL_ICMP_ECHO)) {
		fprintf(stderr, "no ICMP echo reply (type=%d, code=%d)\n",
			icmp->type, icmp->code);
		return -EINVAL;
	}

	return 0;
}

static int seed_rng(const char *rng_seed_str)
{
	int ret, fd;
	size_t len;
	struct {
		int entropy_count;
		int buffer_size;
		unsigned char buffer[128];
	} e;

	if (rng_seed_str == NULL) {
		return -EINVAL;
	}

	memset(&e, 0, sizeof(e));
	len = strlen(rng_seed_str);
	if ((len <= 0) || (len >= sizeof(e.buffer))) {
		return -EINVAL;
	}

	memcpy(e.buffer, rng_seed_str, len);
	e.buffer_size = len;
	e.entropy_count = e.buffer_size * 8;	/* XXX check! */

	/* dev(1,8) = random. dev(1,9) = urandom */
	ret = lkl_sys_mknod("/dev/random", LKL_S_IFCHR | 0644, LKL_MKDEV(1, 8));
	if (ret) {
		return -EIO;
	}

	fd = lkl_sys_open("/dev/random", LKL_O_WRONLY, 0);
	if (fd < 0) {
		return -EIO;
	}

	ret = lkl_sys_ioctl(fd, RNDADDENTROPY, (long)&e);
	lkl_sys_close(fd);
	if (ret) {
		return -EBADF;
	}

	return 0;
}

static int dev_mount(char *dev, char *fstype, char *opts,
		     char *dir)
{
	int ret;
	/*
	 * The kernel copies a full page for opts. PAGE_SIZE is not exported by
	 * LKL...
	 */
	char opts_buf[64 * 1024];

	if ((dev == NULL) || (fstype == NULL) || (dir == NULL)) {
		return -LKL_EINVAL;
	}

	memset(opts_buf, 0, sizeof(opts_buf));
	if (opts != NULL) {
		size_t len = strlen(opts);
		if (len >= sizeof(opts_buf)) {
			return -LKL_E2BIG;
		}
		memcpy(opts_buf, opts, len);
	}

	ret = lkl_sys_mkdir(dir, 0700);
	if (ret && (ret != -LKL_EEXIST)) {
		fprintf(stderr, "failed to create dir at %s: %s.\n",
			dir, lkl_strerror(ret));
		return ret;
	}

	printf("mounting %s filesystem %s at %s\n", fstype, dev, dir);

	ret = lkl_sys_mount(dev, dir, fstype, 0, opts_buf);
	if (ret) {
		fprintf(stderr, "mount failed: %s.\n", lkl_strerror(ret));
		lkl_sys_rmdir(dir);
		return ret;
	}

	return 0;
}

#define WGDEV "wgtest0"

static int wg_setup(int wg_port, unsigned int wg_tun_ip, int wg_tun_nmlen,
		const wg_key_b64_string wg_priv_key_b64,
		const wg_key_b64_string wg_peer_pub_key_b64,
		struct sockaddr_in *peer_ep_saddr)
{
	int ret;
	int wg_ifindex;
	wg_allowedip wildcardip = {
		.family = AF_INET,
		/* zero = allow all */
	};
	wg_peer new_peer = {
		.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS,
		.endpoint.addr4 = *peer_ep_saddr,
		.first_allowedip = &wildcardip,
		.last_allowedip = &wildcardip,
	};
	wg_device new_device = {
		.name = WGDEV,
		.listen_port = wg_port,
		.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT
			| WGDEVICE_REPLACE_PEERS
			| WGDEVICE_HAS_FWMARK, /* wg flags this when unset */
		.first_peer = &new_peer,
		.last_peer = &new_peer
	};

	ret = wg_key_from_base64(&new_device.private_key, wg_priv_key_b64);
	if (ret < 0) {
		fprintf(stderr, "failed to parse b64 private key\n");
		goto err_out;
	}

	ret = wg_key_from_base64(&new_peer.public_key, wg_peer_pub_key_b64);
	if (ret < 0) {
		fprintf(stderr, "failed to parse b64 public key\n");
		goto err_out;
	}

	ret = wg_add_device(new_device.name);
	if (ret < 0) {
		fprintf(stderr, "Unable to add device\n");
		goto err_out;
	}

	ret = lkl_ifname_to_ifindex(new_device.name);
	if (ret < 0) {
		fprintf(stderr, "Unable get device index: %s\n",
			lkl_strerror(ret));
		ret = -ENODEV;
		goto err_dev_del;
	}

	wg_ifindex = ret;

	ret = lkl_if_up(wg_ifindex);
	if (ret < 0) {
		fprintf(stderr, "failed to set tun IP: %s\n",
			lkl_strerror(ret));
		ret = -ENODEV;
		goto err_dev_del;
	}

	ret = wg_set_device(&new_device);
	if (ret < 0) {
		fprintf(stderr, "Unable to set device\n");
		goto err_dev_del;
	}

	ret = lkl_if_set_ipv4(wg_ifindex, wg_tun_ip, wg_tun_nmlen);
	if (ret < 0) {
		fprintf(stderr, "failed to set tun IP: %s\n",
			lkl_strerror(ret));
		ret = -ENODEV;
		goto err_dev_del;
	}

	printf("wireguard interface %s up\n", WGDEV);

	return wg_ifindex;

err_dev_del:
	wg_del_device(WGDEV);
err_out:
	return ret;
}

static int wg_teardown(void)
{
	int ret = lkl_ifname_to_ifindex(WGDEV);
	if (ret < 0) {
		fprintf(stderr, "Unable get device index: %s\n",
			lkl_strerror(ret));
		return -ENODEV;
	}
	ret = lkl_if_down(ret);
	if (ret < 0) {
		fprintf(stderr, "Unable bring device down: %s\n",
			lkl_strerror(ret));
	}

	ret = wg_del_device(WGDEV);
	if (ret < 0) {
		fprintf(stderr, "Unable to delete device\n");
	}

	return 0;
}

static int parse_usb_ids(struct cl_arg *arg, const char *val)
{
	int match = 0;
	unsigned int usb_vendor = 0;
	unsigned int usb_product = 0;

	if (!val)
		return -EINVAL;

	match = sscanf(val, "0x%04x:0x%04x", &usb_vendor, &usb_product);
	if (match == 0)
		match = sscanf(val, "%04x:%04x", &usb_vendor, &usb_product);
	if ((match != 2) || ((usb_vendor | usb_product) & 0xffff0000))
		return -EINVAL;

	*(uint32_t *)arg->store = (usb_vendor << 16 | usb_product);
	return 0;
}

struct cla_args_wg {
	int port;
	unsigned int tun_ip;
	int tun_nmlen;
	const char *priv_key_b64;
	const char *peer_pub_key_b64;
	unsigned int peer_ep_ip;
	int peer_ep_port;
};

static struct {
	const char *tap_if;
	int dhcp, nmlen;
	unsigned int ip, dst;
	const char *rng_seed;
	char *mnt_dev;
	char *mnt_fs_type;
	char *mnt_opts;
	uint32_t usb_vendor_product;
	struct cla_args_wg wg;
} cla = {
	.ip = INADDR_NONE,
	.dst = INADDR_NONE,
	.wg.tun_ip = INADDR_NONE,
	.wg.peer_ep_ip = INADDR_NONE,
};
struct cl_arg args[] = {
	{"tap-if", 'i', "tap interface name", 1, CL_ARG_STR,
	 &cla.tap_if, NULL, NULL},
	{"dhcp", 'd', "use DHCP", 0, CL_ARG_BOOL,
	 &cla.dhcp, NULL, NULL},
	{"ip", 'I', "IPv4 address", 1, CL_ARG_IPV4, &cla.ip, NULL, NULL},
	{"netmask-len", 'n', "IPv4 netmask length", 1, CL_ARG_INT,
	 &cla.nmlen, NULL, NULL},
	{"dst", 'D', "IPv4 address to ping after network setup", 1, CL_ARG_IPV4,
	 &cla.dst, NULL, NULL},
	{"seed", 'S', "entropy string to seed /dev/random", 1, CL_ARG_STR,
	 &cla.rng_seed, NULL, NULL},
	{"mnt-dev", 'M', "device or network target to mount", 1, CL_ARG_STR,
	 &cla.mnt_dev, NULL, NULL},
	{"mnt-fs-type", 'T', "filesystem type to mount", 1, CL_ARG_STR,
	 &cla.mnt_fs_type, NULL, NULL},
	{"mnt-opts", 'O', "mount options", 1, CL_ARG_STR,
	 &cla.mnt_opts, NULL, NULL},
	{"usb", 'u', "passthrough USB device with 0xVENDORID:0xPRODUCTID",
	 1, CL_ARG_USER, &cla.usb_vendor_product, NULL, parse_usb_ids},
	{"wg-port", 'p', "wireguard port", 1, CL_ARG_INT,
	 &cla.wg.port, NULL, NULL},
	{"wg-tun-ip", 't', "wireguard tunnel IPv4 address", 1, CL_ARG_IPV4,
	 &cla.wg.tun_ip, NULL, NULL},
	{"wg-tun-netmask-len", 'm', "wireguard tunnel netmask length", 1,
	 CL_ARG_INT, &cla.wg.tun_nmlen, NULL, NULL},
	{"wg-priv-key", 'k', "wireguard device base64 encoded private key", 1,
	 CL_ARG_STR, &cla.wg.priv_key_b64, NULL, NULL},
	{"wg-peer-pub-key", 'K', "wireguard peer base64 encoded public key", 1,
	 CL_ARG_STR, &cla.wg.peer_pub_key_b64, NULL, NULL},
	{"wg-peer-ep-ip", 'E', "wireguard peer endpoint IPv4 address", 1,
	 CL_ARG_IPV4, &cla.wg.peer_ep_ip, NULL, NULL},
	{"wg-peer-ep-port", 'P', "wireguard peer endpoint port", 1,
	 CL_ARG_INT, &cla.wg.peer_ep_port, NULL, NULL},
	{0},
};

static int args_validate()
{
	if ((cla.ip != LKL_INADDR_NONE) && (cla.nmlen < 0 || cla.nmlen > 32)) {
		fprintf(stderr, "invalid netmask length %d\n", cla.nmlen);
		return -EINVAL;
	}

	if ((cla.ip != LKL_INADDR_NONE) && cla.dhcp) {
		fprintf(stderr, "static IP parameter conflicts with DHCP\n");
		return -EINVAL;
	}

	if ((cla.mnt_dev == NULL) != (cla.mnt_fs_type == NULL)) {
		fprintf(stderr, "mount device only valid with FS type\n");
		return -EINVAL;
	}

	if ((cla.wg.tun_ip != LKL_INADDR_NONE)
	 && (cla.wg.tun_nmlen < 0 || cla.wg.tun_nmlen > 32)) {
		fprintf(stderr, "invalid tun netmask length %d\n",
			cla.wg.tun_nmlen);
		return -EINVAL;
	}

	if ((cla.wg.port != 0)
	 && ((cla.wg.priv_key_b64 == NULL)
					|| (cla.wg.peer_pub_key_b64 == NULL))) {
		fprintf(stderr, "wireguard key parameter(s) missing\n");
		return -EINVAL;
	}

	return 0;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
static int lkl_usb_cfg_mount(void)
{
	char opts_buf[64 * 1024] = { 0 };
	struct lkl_mnt {
		char *dev;
		char *dir;
		char *fstype;
	} mnts[] = { { "proc", "/proc" , "proc" },
		{ "configfs", "/configfs", "configfs" },
		{ "devtmpfs", "/dev", "devtmpfs" } };
	int ret;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mnts); i++) {
		ret = lkl_sys_mkdir(mnts[i].dir, 0700);
		if (ret && (ret != -LKL_EEXIST)) {
			fprintf(stderr, "failed to create dir %s: %s.\n",
				mnts[i].dir, lkl_strerror(ret));
			return ret;
		}

		ret = lkl_sys_mount(mnts[i].dev, mnts[i].dir, mnts[i].fstype,
				    0, opts_buf);
		if (ret < 0) {
			fprintf(stderr, "failed to mount %s: %s.\n",
				mnts[i].dev, lkl_strerror(ret));
			return ret;
		}
	}

	return 0;
}

static int
lkl_path_overwrite(const char *path, char *data, ssize_t data_len,
		   bool sync)
{
	ssize_t written;
	ssize_t wr_ret;
	int fd, ret;

	fd = lkl_sys_open(path, LKL_O_WRONLY | LKL_O_CREAT, 0);
	if (fd < 0) {
		fprintf(stderr, "lkl_sys_open %s: %s\n",
			path, lkl_strerror(fd));
		return fd;
	}

	for (written = 0; written < data_len; written += wr_ret) {
		wr_ret = lkl_sys_write(fd, data + written, data_len - written);
		if (wr_ret <= 0) {
			fprintf(stderr, "lkl_sys_write %s: %s\n",
				path, lkl_strerror(wr_ret));
			ret = -EIO;
			goto err_close;
		}
	}

	if (sync) {
		ret = lkl_sys_fsync(fd);
		if (ret < 0) {
			fprintf(stderr, "lkl_sys_fsync %s: %s\n",
				path, lkl_strerror(ret));
			ret = -EIO;
			goto err_close;
		}
	}
	ret = 0;
err_close:
	lkl_sys_close(fd);
	return ret;
}

unsigned int lkl_usb_gadget_dirid = 0;

static int
lkl_usb_configfs_setup(const struct usb_device_descriptor *device,
		       const struct usb_config_descriptor *config,
		       const struct usb_interface_descriptor *uif)
{
	char configfs_path[LKL_PATH_MAX];
	char configfs_data[256];
	char *subdir_boff;
	size_t subdir_blen;
	unsigned int gadget_subdir = lkl_usb_gadget_dirid;
	int ret;

	ret = snprintf(configfs_path, sizeof(configfs_path),
		       "/configfs/usb_gadget/0x%x/", gadget_subdir);
	if (ret <= 0 || (size_t)ret >= sizeof(configfs_path))
		return -EINVAL;

	/* subdirectory paths are appended to the end */
	subdir_boff = configfs_path + ret;
	subdir_blen = sizeof(configfs_path) - ret;

	/* FIXME should share the same gadget dir when possible */
	lkl_usb_gadget_dirid++;

	ret = lkl_sys_mkdir(configfs_path, 0700);
	if (ret) {
		fprintf(stderr, "failed to create dir %s: %s.\n",
			configfs_path, lkl_strerror(ret));
		return ret;
	}

	ret = snprintf(subdir_boff, subdir_blen, "configs/c.1");
	if (ret <= 0 || (size_t)ret >= subdir_blen)
		return -EINVAL;

	ret = lkl_sys_mkdir(configfs_path, 0700);
	if (ret) {
		fprintf(stderr, "failed to create dir %s: %s.\n",
			configfs_path, lkl_strerror(ret));
		return ret;
	}

	ret = snprintf(subdir_boff, subdir_blen, "functions/ffs.walkley");
	if (ret <= 0 || (size_t)ret >= subdir_blen)
		return -EINVAL;

	ret = lkl_sys_mkdir(configfs_path, 0700);
	if (ret) {
		fprintf(stderr, "failed to create dir %s: %s.\n",
			configfs_path, lkl_strerror(ret));
		return ret;
	}


	ret = snprintf(subdir_boff, subdir_blen, "strings/0x409");
	if (ret <= 0 || (size_t)ret >= subdir_blen)
		return -EINVAL;

	ret = lkl_sys_mkdir(configfs_path, 0700);
	if (ret) {
		fprintf(stderr, "failed to create dir %s: %s.\n",
			configfs_path, lkl_strerror(ret));
		return ret;
	}

	ret = snprintf(subdir_boff, subdir_blen, "configs/c.1/strings/0x409");
	if (ret <= 0 || (size_t)ret >= subdir_blen)
		return -EINVAL;

	ret = lkl_sys_mkdir(configfs_path, 0700);
	if (ret) {
		fprintf(stderr, "failed to create dir %s: %s.\n",
			configfs_path, lkl_strerror(ret));
		return ret;
	}

	ret = snprintf(subdir_boff, subdir_blen, "idProduct");
	if (ret <= 0 || (size_t)ret >= sizeof(configfs_data))
		return -EINVAL;

	ret = snprintf(configfs_data, sizeof(configfs_data),
		       "0x%4x", device->idProduct);
	if (ret <= 0 || (size_t)ret >= sizeof(configfs_data))
		return -EINVAL;

	ret = lkl_path_overwrite(configfs_path, configfs_data, ret, false);
	if (ret < 0)
		return ret;

	ret = snprintf(subdir_boff, subdir_blen, "idVendor");
	if (ret <= 0 || (size_t)ret >= sizeof(configfs_data))
		return -EINVAL;

	ret = snprintf(configfs_data, sizeof(configfs_data),
		       "0x%4x", device->idVendor);
	if (ret <= 0 || (size_t)ret >= sizeof(configfs_data))
		return -EINVAL;

	ret = lkl_path_overwrite(configfs_path, configfs_data, ret, false);
	if (ret < 0)
		return ret;

#if 0
	ret = snprintf(subdir_boff, subdir_blen, "UDC");
	if (ret <= 0 || (size_t)ret >= sizeof(configfs_data))
		return -EINVAL;

	ret = lkl_path_overwrite(configfs_path, "dummy_udc",
				 sizeof("dummy_udc") - 1);
#endif

	return 0;
}

/*
 * parse interface and mass storage eps, returning the amount of data
 * processed.
 */
static ssize_t
host_usb_interface_parse(const struct usb_device_descriptor *device,
			 const struct usb_config_descriptor *config,
			 unsigned char *buf,
			 ssize_t dlen)
{
	struct usb_interface_descriptor *uif
		= (struct usb_interface_descriptor *)buf;
	struct usb_endpoint_descriptor *uep;
	ssize_t dlen_used = 0;

	assert(uif->bDescriptorType == USB_DT_INTERFACE);

	if ((buf + USB_DT_INTERFACE_SIZE < buf)
	 || (USB_DT_INTERFACE_SIZE > dlen)
	 || (uif->bLength != USB_DT_INTERFACE_SIZE)) {
		fprintf(stderr, "bad USB interface desc\n");
		return -EINVAL;
	}
	buf += USB_DT_INTERFACE_SIZE;
	dlen -= USB_DT_INTERFACE_SIZE;
	dlen_used += USB_DT_INTERFACE_SIZE;

	dbg("USB interface Class=%d, SubClass=%d, Protocol=%d, "
	    "Endpoints=%d\n", uif->bInterfaceClass, uif->bInterfaceSubClass,
	    uif->bInterfaceProtocol, uif->bNumEndpoints);

	lkl_usb_configfs_setup(device, config, uif);

	/* parse remaining data, which should carry endpoints */
        while (dlen >= 2) {
                unsigned char this_len = buf[0];
                unsigned char type = buf[1];

		if ((this_len > dlen) || (buf + this_len < buf))
			break;

		if (type == USB_DT_ENDPOINT) {
			uep = (struct usb_endpoint_descriptor *)buf;
			if (this_len != USB_DT_ENDPOINT_SIZE)
				return -EINVAL;

			if (uep->bEndpointAddress & USB_ENDPOINT_DIR_MASK) {
				dbg("-> EP %zd: IN (0x%x)\n",
				    dlen_used, uep->bEndpointAddress);
			} else {
				dbg("-> EP %zd: OUT (0x%x)\n",
				    dlen_used, uep->bEndpointAddress);
			}
			/* TODO add to configfs */
		} else {
			/* e.g. USB_DT_SS[P_ISOC]_ENDPOINT_COMP */
			dbg("-> Skipping non-endpoint type 0x%02x\n", type);
		}
		buf += this_len;
		dlen -= this_len;
		dlen_used += this_len;
	}

out_dlen:
	return dlen_used;
}

static int host_usb_desc_read(uint32_t usb_vendor_product, const char *devname)
{
	ssize_t dlen;
	unsigned char dbuf[4096];
	unsigned char *buf = dbuf;
	struct usb_device_descriptor *device;
	struct usb_config_descriptor *config;
	int dev_fd, ret;

	dev_fd = open(devname, O_RDONLY);
	if (dev_fd < 0) {
		fprintf(stderr,
			"skipping USB device at %s: %d\n",
			devname, errno);
		ret = -errno;
		goto err_out;
	}

	dlen = read(dev_fd, dbuf, sizeof(dbuf));
	if ((dlen < USB_DT_DEVICE_SIZE + USB_DT_CONFIG_SIZE)
	 || (dlen > sizeof(dbuf))) {
		fprintf(stderr, "failed to read USB device desc at %s: %d/%d\n",
			devname, dlen, errno);
		ret = -EIO;
		goto err_close;
	}

	dbg("read %zd bytes data from %s\n", dlen, devname);

	device = (struct usb_device_descriptor *)buf;
	if ((device->bLength != USB_DT_DEVICE_SIZE)
	 || (device->bDescriptorType != USB_DT_DEVICE)) {
		fprintf(stderr, "bad USB device desc at %s\n", devname);
		ret = -ENODEV;
		goto err_close;
	}

	buf += USB_DT_DEVICE_SIZE;
	dlen -= USB_DT_DEVICE_SIZE;

	fprintf(stdout, "%s Vendor=0x%04x Product=0x%04x\n",
		devname, device->idVendor, device->idProduct);

	if ((device->idVendor != (usb_vendor_product >> 16))
	 || (device->idProduct != (usb_vendor_product & 0x0000ffff))) {
		fprintf(stdout, "-> ignored.\n");
		ret = 0;
		goto err_close;
	} else {
		fprintf(stdout, "-> matched, proceeding with passthrough.\n");
	}

	/* buf >= USB_DT_CONFIG_SIZE checked at read time */
	config = (struct usb_config_descriptor *)buf;
	if ((config->bLength != USB_DT_CONFIG_SIZE)
	 || (config->bDescriptorType != USB_DT_CONFIG)) {
		fprintf(stderr, "bad USB config desc at %s\n", devname);
		ret = -ENODEV;
		goto err_close;
	}

	buf += USB_DT_CONFIG_SIZE;
	dlen -= USB_DT_CONFIG_SIZE;

        while (dlen >= 2) {
		ssize_t dlen_used;
                unsigned char this_len = buf[0];
                unsigned char type = buf[1];

		if (this_len > dlen)
			break;

		if (type == USB_DT_INTERFACE) {
			dlen_used = host_usb_interface_parse(device, config,
							     buf, dlen);
			if (dlen_used < 0) {
				ret = dlen_used;
				goto err_close;
			}
			assert(dlen_used <= dlen);
		} else {
			fprintf(stderr,
				"skipping non-interface type 0x%02x\n", type);
			dlen_used = this_len;
		}
		buf += dlen_used;
		dlen -= dlen_used;
	}

	ret = 0;
err_close:
	close(dev_fd);
err_out:
	return ret;
}

static bool numeric_name(const char *n)
{
	const char *orig;

	for (orig = n; isdigit(*n); n++);

	return (*n == '\0' && n != orig);
}

void host_usb_enum(uint32_t usb_vendor_product)
{
	struct dirent *de;
	const char *busbase = "/dev/bus/usb";
	DIR *busdir = opendir(busbase);

	if (busdir == NULL) {
		fprintf(stderr, "failed to open %s: %d\n", busbase, errno);
		return;
	}

	while ((de = readdir(busdir)) != NULL) {
		int l, ret;
		char busname[PATH_MAX];
		DIR *devdir;

		if (!numeric_name(de->d_name))
			continue;

		l = snprintf(busname, sizeof(busname), "%s/%s",
			     busbase, de->d_name);
		if (l < 0 || (size_t)l >= sizeof(busname)) {
			fprintf(stderr, "invalid bus path %s/%s\n",
				busbase, de->d_name);
			continue;
		}

		dbg("checking USB bus at %s\n", busname);
		devdir = opendir(busname);
		if (devdir == NULL) {
			fprintf(stderr, "failed to open %s: %d\n",
				busname, errno);
			continue;
		}

		while ((de = readdir(devdir)) != NULL) {
			char devname[PATH_MAX];

			if (!numeric_name(de->d_name))
				continue;
			l = snprintf(devname, sizeof(devname), "%s/%s",
				     busname, de->d_name);
			if (l < 0 || (size_t)l >= sizeof(devname)) {
				fprintf(stderr, "invalid path %s/%s\n",
					busname, de->d_name);
			}
			dbg("opening USB device at %s\n", devname);

			ret = host_usb_desc_read(usb_vendor_product, devname);
			if (ret < 0) {
				break;
			}
		}
	}
}

int main(int argc, const char **argv)
{
	int ret;
	struct lkl_netdev *nd = NULL;
	int nd_id = 0;
	int nd_ifindex;
	struct timespec walltime;

	ret = parse_args(argc, argv, args);
	if (ret < 0) {
		return -EINVAL;
	}

	ret = args_validate();
	if (ret < 0) {
		return -EINVAL;
	}

	if (cla.tap_if != NULL) {
		nd = lkl_netdev_tap_create(cla.tap_if, 0);
		if (nd == NULL) {
			fprintf(stderr, "failed to add tap if %s\n",
				cla.tap_if);
			return -EINVAL;
		}

		nd_id = lkl_netdev_add(nd, NULL);
		if (nd_id < 0) {
			fprintf(stderr, "failed to add tap netdev: %d\n", nd_id);
			return -EINVAL;
		}
	}

	ret = lkl_start_kernel(&lkl_host_ops,
		"mem=16M loglevel=8 %s", cla.dhcp ? "ip=dhcp" : "");
	if (ret < 0) {
		fprintf(stderr, "failed to start kernel: %d\n", ret);
		return ret;
	}

	/*
	 * wireguard uses a time based seqnum, so the clock needs to be set for
	 * successful reconnect.
	 */
	ret = clock_gettime(CLOCK_REALTIME, &walltime);
	if (ret < 0) {
		fprintf(stderr, "host clock_gettime() failed: %d\n", errno);
		return -EFAULT;
	}
	ret = lkl_sys_clock_settime(CLOCK_REALTIME, &walltime);
	if (ret < 0) {
		fprintf(stderr, "lkl_sys_clock_settime() failed: %d\n", ret);
		return ret;
	}

	if (cla.rng_seed != NULL) {
		ret = seed_rng(cla.rng_seed);
		if (ret < 0) {
			fprintf(stderr, "RNG seeding failed: %d. "
				"May stall with low entropy\n", ret);
		}
	}

	if (cla.tap_if != NULL) {
		nd_ifindex = lkl_netdev_get_ifindex(nd_id);
		if (nd_ifindex < 0) {
			fprintf(stderr, "failed to get ifindex for netdev id "
				"%d: %s\n", nd_id, lkl_strerror(nd_ifindex));
			ret = -ENFILE;
			goto out_halt;
		}

		ret = lkl_if_up(nd_ifindex);
		if (ret < 0) {
			fprintf(stderr, "failed to bring up tap: %d\n", ret);
			goto out_halt;
		}

		if (cla.ip != INADDR_NONE) {
			ret = lkl_if_set_ipv4(nd_ifindex, cla.ip, cla.nmlen);
			if (ret < 0) {
				fprintf(stderr, "failed to set IPv4 address: "
					"%s\n", lkl_strerror(ret));
				goto out_halt;
			}
		}
	}

	if (cla.usb_vendor_product) {
		ret = lkl_usb_cfg_mount();
		if (!ret)
			host_usb_enum(cla.usb_vendor_product);
	}

	if (cla.wg.port != 0) {
		struct sockaddr_in peer_ep_saddr;

		memset(&peer_ep_saddr, 0, sizeof(peer_ep_saddr));
		if (cla.wg.peer_ep_ip != INADDR_NONE) {
			peer_ep_saddr.sin_family = AF_INET;
			peer_ep_saddr.sin_addr.s_addr = cla.wg.peer_ep_ip;
			peer_ep_saddr.sin_port = htons(cla.wg.peer_ep_port);
		}

		ret = wg_setup(cla.wg.port, cla.wg.tun_ip, cla.wg.tun_nmlen,
			       cla.wg.priv_key_b64, cla.wg.peer_pub_key_b64,
			       &peer_ep_saddr);
		if (ret < 0) {
			goto out_halt;
		}
	}

	if (cla.dst != INADDR_NONE) {
		ret = icmp_txrx(cla.dst);
		if (ret < 0) {
			fprintf(stderr, "failed icmp exchange: %s\n",
				strerror(-ret));
			goto out_wg_teardown;
		}
		printf("ping successful\n");
	}

	if (cla.mnt_dev != NULL) {
		ret = dev_mount(cla.mnt_dev, cla.mnt_fs_type, cla.mnt_opts,
				"/mnt");
		if (ret < 0) {
			fprintf(stderr, "mount failed: %s\n",
				lkl_strerror(ret));
			goto out_wg_teardown;
		}
	}

	dbg_cli("walkley");

	if (cla.mnt_dev != NULL) {
		ret = lkl_umount_timeout("/mnt", 0,
					 1000);	/* 1s timeout */
		if (ret < 0) {
			fprintf(stderr, "umount failed: %s\n",
				lkl_strerror(ret));
			goto out_wg_teardown;
		}
	}

	ret = 0;
out_wg_teardown:
	if (cla.wg.port != 0) {
		wg_teardown();
	}
out_halt:
	if (cla.tap_if != NULL) {
		/* needs to be done before halt */
		lkl_netdev_remove(nd_id);
		lkl_netdev_free(nd);
	}
	lkl_sys_halt();
	return ret;
}
