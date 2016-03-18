#include <stdlib.h>
#include <netinet/in.h>
#include <signal.h>
#include "server.h"

static struct http_server server;

void handle_request(struct http_request *request, int fd)
{
}

void sigint_handler(int signo)
{
	exit(0);
}

int main(void)
{
	memset(&server, 0, sizeof(struct http_server));
	server.listen_addr.sin_family = AF_INET;
	server.listen_addr.sin_port = htons(5001);
	server.listen_addr.sin_addr.s_addr = INADDR_ANY;
	server.handle_request = handle_request;
	server.data = "this is my string";

	//ingnore SIGPIPE
	struct sigaction on_sigpipe;
	on_sigpipe.sa_handler = SIG_IGN;
	sigemptyset(&on_sigpipe.sa_mask);
	sigaction(SIGPIPE, &on_sigpipe, NULL);

	//handle Ctrl+c
	struct sigaction on_sigint;
	on_sigint.sa_handler = sigint_handler;
	sigemptyset(&on_sigint.sa_mask);
	on_sigint.sa_flags = 0;
	sigaction(SIGINT, &on_sigint, NULL);

	return http_server_loop(&server);
}
