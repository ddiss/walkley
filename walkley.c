// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
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

#include "cla.h"

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
	saddr.sin_family = AF_INET;
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

extern void dbg_entrance(void);

static struct {
	const char *tap_if;
	int dhcp, nmlen;
	unsigned int ip, dst;
	const char *rng_seed;
	char *mnt_dev;
	char *mnt_fs_type;
	char *mnt_opts;
} cla = {
	.ip = INADDR_NONE,
	.dst = INADDR_NONE,
};
struct cl_arg args[] = {
	{"tap-if", 'i', "tap interface name", 1, CL_ARG_STR,
	 &cla.tap_if, NULL, NULL},
	{"dhcp", 'd', "use DHCP", 0, CL_ARG_BOOL,
	 &cla.dhcp, NULL, NULL},
	{"ip", 'I', "IPv4 address", 1, CL_ARG_IPV4, &cla.ip, NULL, NULL},
	{"netmask-len", 'n', "IPv4 netmask length", 1, CL_ARG_INT,
	 &cla.nmlen, NULL, NULL},
	{"dst", 'D', "IPv4 destination address", 1, CL_ARG_IPV4,
	 &cla.dst, NULL, NULL},
	{"seed", 'S', "entropy string to seed /dev/random", 1, CL_ARG_STR,
	 &cla.rng_seed, NULL, NULL},
	{"mnt-dev", 'M', "device or network target to mount", 1, CL_ARG_STR,
	 &cla.mnt_dev, NULL, NULL},
	{"mnt-fs-type", 'T', "filesystem type to mount", 1, CL_ARG_STR,
	 &cla.mnt_fs_type, NULL, NULL},
	{"mnt-opts", 'O', "mount options", 1, CL_ARG_STR,
	 &cla.mnt_opts, NULL, NULL},
	{0},
};

int main(int argc, const char **argv)
{
	int ret;
	struct lkl_netdev *nd = NULL;
	int nd_id = 0;
	int nd_ifindex;

	if (parse_args(argc, argv, args) < 0)
		return -EINVAL;

	if (cla.ip != LKL_INADDR_NONE && (cla.nmlen < 0 || cla.nmlen > 32)) {
		fprintf(stderr, "invalid netmask length %d\n", cla.nmlen);
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

		printf("got nd_id %d\n", nd_id);
	}

	ret = lkl_start_kernel(&lkl_host_ops,
		"mem=16M loglevel=8 %s", cla.dhcp ? "ip=dhcp" : "");
	if (ret < 0) {
		fprintf(stderr, "failed to start kernel: %d\n", ret);
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

		/* XXX call with 1 if tap_if isn't set? */
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

	if (cla.dst != INADDR_NONE) {
		ret = icmp_txrx(cla.dst);
		if (ret < 0) {
			fprintf(stderr, "failed icmp exchange: %s\n",
				strerror(-ret));
			goto out_halt;
		}
		printf("ping successful\n");
	}

	if (cla.mnt_dev != NULL) {
		ret = dev_mount(cla.mnt_dev, cla.mnt_fs_type, cla.mnt_opts,
				"/mnt");
		if (ret < 0) {
			fprintf(stderr, "mount failed: %s\n",
				lkl_strerror(ret));
			goto out_halt;
		}
	}

	printf("dropping into dbg shell...\n");
	dbg_entrance();

	if (cla.mnt_dev != NULL) {
		ret = lkl_umount_timeout("/mnt", 0,
					 1000);	/* 1s timeout */
		if (ret < 0) {
			fprintf(stderr, "umount failed: %s\n",
				lkl_strerror(ret));
			goto out_halt;
		}
	}

	ret = 0;
out_halt:
	if (cla.tap_if != NULL) {
		/* needs to be done before halt */
		lkl_netdev_remove(nd_id);
		lkl_netdev_free(nd);
	}
	lkl_sys_halt();
	return ret;
}
