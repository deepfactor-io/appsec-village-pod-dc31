/*
 * exercise2a.c
 *
 * Sample program; used in conjunction with libexercise2.so to illustrate
 * library API monitoring.
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
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SHADOW_FILE "/etc/shadow"
#define CONN_HOST "www.google.com"
#define CONN_PORT 443

int
main(int argc, char **argv)
{
	int sock_fd, r;
	uint32_t rmtaddr;
	uint16_t rmtport;
	struct addrinfo hints, *res;
	struct sockaddr_in *sin;

	printf("Attempting to open %s\n", SHADOW_FILE);
	(void)open(SHADOW_FILE, O_RDONLY);

	printf("Attempting DNS resolution of %s\n", CONN_HOST);
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(CONN_HOST, NULL, &hints, &res);
	if (r) {
		printf("Error: %s\n", gai_strerror(r));
		exit(1);
	}

	if (res == NULL)
		errx(1, "Error: no DNS records returned.\n");

	sin = (struct sockaddr_in *)res->ai_addr;
	rmtaddr = ntohl((uint32_t)(sin->sin_addr.s_addr));
	sin->sin_port = htons(CONN_PORT);

	printf("Attempting connection to %d.%d.%d.%d:%d\n",
	    (rmtaddr & 0xFF000000) >> 24,
	    (rmtaddr & 0xFF0000) >> 16,
	    (rmtaddr & 0xFF00) >> 8,
	    (rmtaddr & 0xFF),
	    CONN_PORT);

	sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock_fd == -1)
		err(1, "socket");

	if (connect(sock_fd, res->ai_addr, res->ai_addrlen) == -1)
		err(1, "connect");

	printf("Success! Check logs in /tmp/exercise2.log to see what was "
	    "observed.\n");

	(void)close(sock_fd);

	return 0;
}
