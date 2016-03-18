#include "server.h"
#include <ev.h>
#include <fcntl.h>
#include "list.h"

static inline int setnonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if(flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	if(fcntl(fd, F_SETFL, flags) < 0)
		return -1;

	return 0;
}

void delete_http_request(struct http_request *request)
{
	
}

static struct http_request* parse_request(char *request_data, int len)
{
	return NULL;
}

static void write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	if(!(revents & EV_WRITE)){
		ev_io_stop(EV_A_ w);
		return;
	}

	struct client *client = (struct client*)((char *)w - offsetof(struct client,  ev_write));
	struct http_request *request = client->request;
	if(!request){
		write(client->fd, "HTTP/1.1 400 Bad Request\r\n\r\n", 24);
		close(client->fd);
		free(client->request_data);
		free(client);
	}

	client->handle_request(request, client->fd);
	delete_http_request(request);
	free(client->request_data);
	free(client);
	ev_io_stop(EV_A_ w);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	int len = 0, sum = 0;
	if(!(revents & EV_READ)){
		ev_io_stop(EV_A_ w);;
		return;
	}
	struct client *client = 
		(struct client*)((char *)w - offsetof(struct client, ev_read));

	char *buff[REQUEST_BUFFER_SIZE + 1];
	client->request_data = NULL;

	do{
		len = read(client->fd, buff, REQUEST_BUFFER_SIZE);
		sum += len;
		if(len  < REQUEST_BUFFER_SIZE)
			buff[len] = '\0';
		if(client->request_data == NULL){
			client->request_data = malloc(len + 1);
			memcpy(client->request_data,  buff, len);
		}else{
			client->request_data = realloc(client->request_data, sum + 1);
			memcpy(client->request_data+sum-len, buff, len);
		}
	}while(len == REQUEST_BUFFER_SIZE);
	client->request = NULL;
	client->request = parse_request(client->request_data, sum);
	ev_io_stop(EV_A_ w);
	ev_io_init(&client->ev_write, write_cb, client->fd, EV_WRITE);
	ev_io_start(loop, &client->ev_write);
}


static void accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct client* main_client = 
		(struct client*)((char *)w - offsetof(struct client, ev_accept));
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(struct sockaddr_in);
	int  client_fd = accept(w->fd, (struct sockaddr*)&client_addr, &client_len);
	if(client_fd  < 0){
		return;
	}

	if(setnonblock(client_fd) < 0){
		return;
	}

	struct client *client = malloc(sizeof(struct client));

	client->handle_request = main_client->handle_request;
	client->data = main_client->data;
	client->fd = client_fd;

	ev_io_init(&client->ev_read, read_cb, client->fd, EV_READ);
	ev_io_start(loop, &client->ev_read);
}

int http_server_loop(struct http_server *server, int fd)
{
	server->loop = ev_default_loop(0);
	server->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(server->listen_fd < 0){
		perror("listen failed(socket)");
		return -1;
	}

	int reuseaddr_on = 1;
	if(setsockopt(server->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, sizeof(server->listen_addr)) < 0){
			perror("setsockopt failed");
			return -1;
	}

	struct sockaddr *listen_addr = (struct sockaddr*)&server->listen_addr;

	if(bind(server->listen_fd, listen_addr, sizeof(*listen_addr)) < 0){
		perror("bind failed");
		return -1;
	}

	if(listen(server->listen_fd, 5) < 0){
		perror("listen failed");
		return -1;
	}

	if(setnonblock(server->listen_fd) < 0){
		perror("setnonblock failed");
		return -1;
	}

	struct client *main_client = malloc(sizeof(struct client));
	if(!main_client){
		perror("malloc failed");
		return -1;
	}
	memset(main_client, 0, sizeof(struct client));
	main_client->handle_request = server->handle_request;
	main_client->data = server->data;
	ev_io_init(&main_client->ev_accept, accept_cb, server->listen_fd, EV_READ);
	ev_io_start(server->loop, &main_client->ev_accept);
	server->ev_accept = &main_client->ev_accept;
	ev_loop(server->loop, 0);

	return 0;
}
