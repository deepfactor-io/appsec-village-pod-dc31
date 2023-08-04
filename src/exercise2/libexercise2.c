/*
 * libexercise2.c
 *
 * LD_PRELOAD library implementation for security tool evasion workshop
 *
 * (c) 2023 Deepfactor, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <err.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

int (*real_open)(const char *, int, mode_t);
int (*real_connect)(int, const struct sockaddr *, socklen_t);
int (*real_getaddrinfo)(const char *, const char *, const struct addrinfo *,
    struct addrinfo **);

FILE *f_log;
#define LOG_FILE "/tmp/exercise2.log"

extern char *__progname;

int
open(const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode = 0;

	if (flags & O_CREAT) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	fprintf(f_log, "(%s, pid %d): %s: Observed access to pathname %s "
	    "(flags=0x%x)\n", __progname, getpid(), __func__, pathname, flags);

	return real_open(pathname, flags, mode);
}

int
getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
    struct addrinfo **res)
{
	fprintf(f_log, "(%s, pid %d): %s: Observed DNS resolution request for "
	    "node %s", __progname, getpid(), __func__, node);

	if (service)
		fprintf(f_log, ", service %s", service);

	fprintf(f_log, "\n");

	return real_getaddrinfo(node, service, hints, res);
}

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
	uint32_t rmtaddr;
	uint16_t rmtport;

	if (addr->sa_family == AF_INET) {
		rmtaddr = ntohl((uint32_t)(inaddr->sin_addr.s_addr));
		rmtport = ntohs(inaddr->sin_port);

		fprintf(f_log, "(%s, pid %d): %s: Observed connection request "
		    "to %d.%d.%d.%d:%d\n", __progname, getpid(), __func__,
		    (rmtaddr & 0xFF000000) >> 24,
		    (rmtaddr & 0xFF0000) >> 16,
		    (rmtaddr & 0xFF00) >> 8,
		    (rmtaddr & 0xFF),
		    rmtport);
	}

	return real_connect(sockfd, addr, addrlen);
}

void __attribute__ ((constructor))
libexercise2_init(void)
{
	void *libc_handle;

	libc_handle = dlmopen(LM_ID_BASE, "libc.so.6", RTLD_LAZY);
	if (libc_handle == NULL)
		err(1, "dlmopen");

	real_open = dlsym(libc_handle, "open");
	if (real_open == NULL)
		err(1, "dlsym(open)");

	real_connect = dlsym(libc_handle, "connect");
	if (real_connect == NULL)
		err(1, "dlsym(connect)");

	real_getaddrinfo = dlsym(libc_handle, "getaddrinfo");
	if (real_getaddrinfo == NULL)
		err(1, "dlsym(getaddrinfo)");

	f_log = fopen(LOG_FILE, "a");
	if (f_log == NULL)
		err(1, "fopen");
}
