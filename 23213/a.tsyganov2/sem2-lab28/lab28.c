#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include <netdb.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#define BUF_SIZE 4096
#define PAGE_LINES 25

static struct termios old_termios;

typedef struct {
	char *protocol;
	char *user;
	char *hostname;
	char *port_str;
	int port;
	char *uri;
} url_info;

static void free_url_info(url_info *info) {
	free(info->protocol);
	free(info->user);
	free(info->hostname);
	free(info->port_str);
	free(info->uri);
}

static char *copy_match(const char *s, regmatch_t *m, int i) {
	if (m[i].rm_so == -1) return NULL;
	int len = m[i].rm_eo - m[i].rm_so;
	char *res = malloc(len + 1);
	if (!res) return NULL;
	memcpy(res, s + m[i].rm_so, len);
	res[len] = '\0';
	return res;
}

static int parse_url(const char *url, url_info *info) {
	const char *regex = "^([a-z]+)://(([^@]*)@)?([^:/]+)(:([0-9]+))?(.*)$";
	regex_t re;
	regmatch_t matches[10];
	if (regcomp(&re, regex, REG_EXTENDED)) return -1;
	if (regexec(&re, url, 10, matches, 0)) {
		regfree(&re);
		return -1;
	}

	info->protocol = copy_match(url, matches, 1);
	info->user	= copy_match(url, matches, 3);
	info->hostname = copy_match(url, matches, 4);
	info->port_str = copy_match(url, matches, 6);
	info->uri 	= copy_match(url, matches, 7);
	if (!info->uri || info->uri[0] == '\0') {
		free(info->uri);
		info->uri = strdup("/");
	}
	info->port = info->port_str ? atoi(info->port_str) : 80;

	regfree(&re);
	return 0;
}

static int open_socket(const char *hostname, int port) {
	struct hostent *he = gethostbyname(hostname);
	if (!he) {
		fprintf(stderr, "DNS error for %s\n", hostname);
		return -1;
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port)
	};
	memcpy(&addr.sin_addr, he->h_addr, he->h_length);

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(sock);
		return -1;
	}

	return sock;
}

static void enable_raw_mode() {
	struct termios raw;
	if (tcgetattr(STDIN_FILENO, &old_termios) < 0) {
		perror("tcgetattr");
		exit(EXIT_FAILURE);
	}
	raw = old_termios;
	raw.c_lflag &= ~(ICANON | ECHO);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) < 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}
}

static void disable_raw_mode() {
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
}

static int buffer_space(int start, int end) {
	if (end >= start) {
		return (start == 0) ? BUF_SIZE - end - 1 : BUF_SIZE - end;
	}
	else {
		return start - end - 1;
	}
}


static int run_http_client(const char *hostname, int port, const char *uri) {
	int sock = open_socket(hostname, port);
	if (sock < 0) return EXIT_FAILURE;

	enable_raw_mode();

	char *request = NULL;
	if (asprintf(&request,
		"GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
		uri, hostname) == -1) {
		perror("asprintf");
		disable_raw_mode();
		close(sock);
		return EXIT_FAILURE;
	}
	write(sock, request, strlen(request));
	free(request);

	char buffer[BUF_SIZE];
	int start = 0, end = 0;
	int lines = 0, eof = 0;

	while (1) {
		fd_set readfds, writefds;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		int has_full_line = 0;
		for (int i = start; i != end; i = (i + 1) % BUF_SIZE) {
			if (buffer[i] == '\n') {
				has_full_line = 1;
				break;
			}
		}

		if (buffer_space(start, end) > 0 && !eof) {
			FD_SET(sock, &readfds);
		}
		if (lines < PAGE_LINES && has_full_line) {
			FD_SET(STDOUT_FILENO, &writefds);
		}
		if (lines >= PAGE_LINES) {
			FD_SET(STDIN_FILENO, &readfds);
		}

		if (FD_ISSET(sock, &readfds) == 0 &&
		    FD_ISSET(STDOUT_FILENO, &writefds) == 0 &&
		    FD_ISSET(STDIN_FILENO, &readfds) == 0 &&
		    eof && start == end) {
			break;
		}

		int maxfd = sock > STDIN_FILENO ? sock : STDIN_FILENO;
		if (select(maxfd + 1, &readfds, &writefds, NULL, NULL) < 0) {
			perror("select");
			disable_raw_mode();
			close(sock);
			return EXIT_FAILURE;
		}

		if (FD_ISSET(sock, &readfds) && !eof) {
			int space = buffer_space(start, end);
			int right = (end >= start) ? BUF_SIZE - end : start - end - 1;
			int n = read(sock, buffer + end, space < right ? space : right);
			if (n <= 0) {
				eof = 1;
			} else {
				end = (end + n) % BUF_SIZE;
			}
		}

		if (FD_ISSET(STDOUT_FILENO, &writefds) && has_full_line && lines < PAGE_LINES) {
			int i = start;
			while (i != end && buffer[i] != '\n') i = (i + 1) % BUF_SIZE;
			if (i == end) continue;
			i = (i + 1) % BUF_SIZE;

			int len = (i > start) ? (i - start) : (BUF_SIZE - start);
			if (write(STDOUT_FILENO, buffer + start, len) < 0) break;
			start = i;
			lines++;
		}

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			char c;
			read(STDIN_FILENO, &c, 1);
			if (c == ' ') lines = 0;
		}
	}

	close(sock);
	disable_raw_mode();
	return EXIT_SUCCESS;
}


int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s URL\n", argv[0]);
		return EXIT_FAILURE;
	}

	url_info info;
	if (parse_url(argv[1], &info) != 0) {
		fprintf(stderr, "Failed to parse URL\n");
		return EXIT_FAILURE;
	}

	if (strcmp(info.protocol, "http") != 0) {
		fprintf(stderr, "Only http:// URLs are supported\n");
		free_url_info(&info);
		return EXIT_FAILURE;
	}

	if (info.user != NULL) {
		fprintf(stderr, "User info in URL is not supported\n");
		free_url_info(&info);
		return EXIT_FAILURE;
	}

	int result = run_http_client(info.hostname, info.port, info.uri);
	free_url_info(&info);
	return result;
}
