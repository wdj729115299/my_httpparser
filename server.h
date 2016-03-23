#ifndef _SERVER_H
#define _SERVER_H

#include <netinet/in.h>
#include <ev.h>
#include "list.h"

#define alloc_cpy(dest, src, len) \
    dest = malloc(len + 1);\
    memcpy(dest, src, len);\
    dest[len] = '\0';

#define REQUEST_BUFFER_SIZE 2048

struct http_header{
	char *name, *value;
	struct list_head list;
};

struct http_request{
	char method;
	char *url;
	char *body;
	unsigned int flags;
	unsigned short http_major;
	unsigned short http_minor;
	struct http_header *header;
	void *data;
};

struct http_server{
	struct ev_loop *loop;
	struct sockaddr_in listen_addr;
	int listen_fd;
	void (*handle_request)(struct http_request *request, int fd);
	struct ev_io *ev_accept;
	void *data;
};

struct client{
	int fd;
	ev_io ev_accept;
	ev_io ev_read;
	ev_io ev_write;
	char *request_data;
	struct http_request *request;
	void (*handle_request)(struct http_request *request, int fd);
	void *data;
};

#endif
