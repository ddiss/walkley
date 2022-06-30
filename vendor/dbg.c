#include <errno.h>
#include <lkl.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char* PROMOTE = "$";
#define str(x) #x
#define xstr(s) str(s)
#define MAX_BUF 100
static char cmd[MAX_BUF];
static char argv[10][MAX_BUF];
static int argc = 0;
static char cur_dir[MAX_BUF] = "/";

static char* normalize_path(const char * src, size_t src_len) {
        char* res;
        unsigned int res_len;
        const char* ptr = src;
        const char* end = &src[src_len];
        const char* next;

	res = malloc((src_len > 0 ? src_len : 1) + 1);
	res_len = 0;

        for (ptr = src; ptr < end; ptr=next+1) {
                size_t len;
                next = memchr(ptr, '/', end-ptr);
                if (next == NULL) {
                        next = end;
                }
                len = next-ptr;
                switch(len) {
                case 2:
                        if (ptr[0] == '.' && ptr[1] == '.') {
                                const char * slash = strrchr(res, '/');
                                if (slash != NULL) {
                                        res_len = slash - res;
                                }
                                continue;
                        }
                        break;
                case 1:
                        if (ptr[0] == '.') {
                                continue;
                        }
                        break;
                case 0:
                        continue;
                }
                res[res_len++] = '/';
                memcpy(&res[res_len], ptr, len);
                res_len += len;
        }
        if (res_len == 0) {
                res[res_len++] = '/';
        }
        res[res_len] = '\0';
        return res;
}

static void build_path(char* path) {
	char* npath;

	strcpy(path, cur_dir);
	if (argc >=1) {
		if (argv[0][0] == '/') strncpy(path, argv[0], LKL_PATH_MAX);
		else {
			strncat(path, "/", LKL_PATH_MAX - strlen(path) - 1);
			strncat(path, argv[0], LKL_PATH_MAX - strlen(path) - 1);
		}
	}
	npath = normalize_path(path, strlen(path));
	strcpy(path, npath);
	free(npath);
}

static void ls() {
	char path[LKL_PATH_MAX];
	struct lkl_dir* dir;
	struct lkl_linux_dirent64* de;
	int err;

	build_path(path);
	dir = lkl_opendir(path, &err);
	if (dir) {
		do {
			de = lkl_readdir(dir);
			if (de) {
				printf("%s\n", de->d_name);
			} else {
				err = lkl_errdir(dir);
				if (err != 0) {
					fprintf(stderr, "%s\n",
						lkl_strerror(err));
				}
				break;
			}
		} while(1);
		lkl_closedir(dir);
	} else {
		fprintf(stderr, "%s: %s\n", path, lkl_strerror(err));
	}
}

static void cd() {
	char path[LKL_PATH_MAX];
	struct lkl_dir* dir;
	int err;

	build_path(path);
	dir = lkl_opendir(path, &err);
	if (dir) {
		strcpy(cur_dir, path);
		lkl_closedir(dir);
	} else {
		fprintf(stderr, "%s: %s\n", path, lkl_strerror(err));
	}
}

static void mount() {
	int ret = 0;
	struct dbg_mnt {
		char *fstype;
		char *dev;
		char *dir;
		char *opts;
	} m;

	memset(&m, 0, sizeof(m));
	if ((argc != 1) && (argc != 3) && (argc != 4)) {
		fprintf(stderr, "invalid mount parameters.\n");
		return;
	}

	m.fstype = argv[0];
	if (argc == 1) {
		/* default behaviour - single arg mounts fstype under /fstype */
		m.fstype = argv[0];
		ret = lkl_mount_fs(m.fstype);
		if (ret == 1)
			fprintf(stderr, "%s is already mounted.\n", m.fstype);
		return;
	}

	m.dev = argv[1];
	m.dir = argv[2];
	if (argc == 4)
		m.opts = argv[3];	/* optional */

	printf("calling mount with (%s, %s, %s, %s).\n",
		m.fstype, m.dev, m.dir, m.opts);

	ret = lkl_sys_mkdir(m.dir, 0xff);
	if (ret && ret != -LKL_EEXIST) {
		fprintf(stderr, "failed to create dir at %s: %d.\n",
			m.dir, ret);
		return;
	}

	ret = lkl_sys_mount(m.dev, m.dir, m.fstype, 0, m.opts);
	if (ret && ret != -LKL_EBUSY) {
		fprintf(stderr, "mount failed: %d.\n", ret);
		lkl_sys_rmdir(m.dir);
		return;
	}
}

static void cat() {
	char path[LKL_PATH_MAX];
	int ret;
	char buf[1024];
	int fd;

	if (argc != 1) {
		fprintf(stderr, "%s\n", "One argument is needed.");
		return;
	}

	build_path(path);
	fd = lkl_sys_open(path, LKL_O_RDONLY, 0);

	if (fd < 0) {
		fprintf(stderr, "lkl_sys_open %s: %s\n",
			path, lkl_strerror(fd));
		return;
	}

	while ((ret = lkl_sys_read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[ret] = '\0';
		printf("%s", buf);
	}

	if (ret) {
		fprintf(stderr, "lkl_sys_read %s: %s\n",
			path, lkl_strerror(ret));
	}
	lkl_sys_close(fd);
}

static void cp() {
	char in_path[LKL_PATH_MAX];
	char out_path[LKL_PATH_MAX];
	ssize_t rd_ret, wr_ret;
	char buf[4096];
	int in_fd, out_fd;

	if (argc != 2) {
		fprintf(stderr, "%s\n", "Two arguments are needed.");
		goto out;
	}

	build_path(in_path);
	in_fd = lkl_sys_open(in_path, LKL_O_RDONLY, 0);
	if (in_fd < 0) {
		fprintf(stderr, "lkl_sys_open %s: %s\n",
			in_path, lkl_strerror(in_fd));
		goto out;
	}

	build_path(out_path);
	out_fd = lkl_sys_open(out_path, LKL_O_WRONLY | LKL_O_CREAT, 0);
	if (out_fd < 0) {
		fprintf(stderr, "lkl_sys_open %s: %s\n",
			out_path, lkl_strerror(out_fd));
		goto infd_close;
	}

	while ((rd_ret = lkl_sys_read(in_fd, buf, sizeof(buf))) > 0) {
		ssize_t written;
		for (written = 0; written < rd_ret; written += wr_ret) {
			wr_ret = lkl_sys_write(out_fd, buf + written,
					       rd_ret - written);
			if (wr_ret <= 0) {
				fprintf(stderr, "lkl_sys_write %s: %s\n",
					out_path, lkl_strerror(wr_ret));
				goto outfd_close;
			}
		}
	}

	if (rd_ret) {
		fprintf(stderr, "lkl_sys_read %s: %s\n",
			in_path, lkl_strerror(rd_ret));
		goto outfd_close;
	}

	wr_ret = lkl_sys_fsync(out_fd);
	if (wr_ret < 0) {
		fprintf(stderr, "lkl_sys_fsync %s: %s\n",
			out_path, lkl_strerror(wr_ret));
		goto outfd_close;
	}
outfd_close:
	lkl_sys_close(out_fd);
infd_close:
	lkl_sys_close(in_fd);
out:
	return;
}

static void overwrite() {
	char path[LKL_PATH_MAX];
	int ret;
	int fd;
	char buf[1024];

	build_path(path);
	fd = lkl_sys_open(path, LKL_O_WRONLY | LKL_O_CREAT, 0);
	if (fd < 0) {
		fprintf(stderr, "lkl_sys_open %s: %s\n",
			path, lkl_strerror(fd));
		return;
	}
	printf("Input the content and stop by hitting Ctrl-D:\n");
	while(fgets(buf, 1023, stdin)) {
		ret = lkl_sys_write(fd, buf, strlen(buf));
		if (ret < 0) {
			fprintf(stderr, "lkl_sys_write %s: %s\n",
				path, lkl_strerror(fd));
		}
	}
	lkl_sys_close(fd);
}

static void pwd() {
	printf("%s\n", cur_dir);
}

static int parse_cmd(char* input) {
	char* token;
	token = strtok(input, " ");
	if (token) strcpy(cmd, token);
	else  return -1;

	argc = 0;
	token = strtok(NULL, " ");
	while(token) {
		if (argc >=10) {
			fprintf(stderr, "To many args > 10\n");
			return -1;
		}
		strcpy(argv[argc++], token);
		token = strtok(NULL, " ");
	}
	return 0;
}

static void help(void);

static struct dbg_cmd {
	char *name;
	char *usage;
	char *desc;
	void (*cmd_cb)(void);
} dcmds[] = { { "cat", "cat FILE", "Show content of FILE", cat },
	{ "cd", "cd [DIR]", "Change directory to DIR", cd },
	{ "cp", "cp INFILE OUTFILE", "Copy INFILE contents to OUTFILE", cp },
	{ "help", "help", "Show this message", help },
	{ "ls", "ls [DIR]", "List files in DIR", ls },
	{ "mount", "mount FSTYPE [DEV DIR OPTS]",
	  "Mount FSTYPE as /FSTYPE or DEV at DIR with OPTS", mount },
	{ "overwrite", "overwrite FILE",
	  "Overwrite content of FILE from stdin", overwrite },
	{ "pwd", "pwd", "Show current directory", pwd },
	{ "exit", "exit", "Exit the debug session", NULL },
	/* terminator must be last... */
	{ NULL } };

static void help() {
	const struct dbg_cmd *dcmd;

	for (dcmd = dcmds; dcmd->name != NULL; dcmd++)
		printf("%s\n\t%s\n", dcmd->usage, dcmd->desc);
}

static void run_cmd() {
	const struct dbg_cmd *dcmd;

	for (dcmd = dcmds; dcmd->name != NULL; dcmd++) {
		if (!strcmp(dcmd->name, cmd) && dcmd->cmd_cb)
			return dcmd->cmd_cb();
	}
	if (dcmd->name == NULL)
		fprintf(stderr, "Unknown command: %s\n", cmd);
}

void dbg_cli() {
	char input[MAX_BUF + 1];
	int ret;
	int c;

	printf("Type help to see a list of commands\n");
	do {
		printf("%s ", PROMOTE);
		ret = scanf("%" xstr(MAX_BUF) "[^\n]s", input);
		while ((c = getchar()) != '\n' && c != EOF);
		if (ret == 0)
			continue;
		if (ret != 1 && errno != EINTR) {
			perror("scanf");
			continue;
		}
		if (strlen(input) == MAX_BUF) {
			fprintf(stderr, "Too long input > %d\n", MAX_BUF - 1);
			continue;
		}
		if (parse_cmd(input))
			continue;
		if (strcmp(cmd, "exit") == 0)
			break;
		run_cmd();
	} while(1);
}
