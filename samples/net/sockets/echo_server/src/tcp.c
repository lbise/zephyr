/* tcp.c - TCP specific code for echo server */

/*
 * Copyright (c) 2017 Intel Corporation.
 * Copyright (c) 2018 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_DECLARE(net_echo_server_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include <net/socket.h>
#include <net/tls_credentials.h>

#include "common.h"
#include "certificate.h"

#define MAX_CLIENT_QUEUE CONFIG_NET_SAMPLE_NUM_HANDLERS

#if defined(CONFIG_NET_IPV4)
K_THREAD_STACK_ARRAY_DEFINE(tcp4_handler_stack, CONFIG_NET_SAMPLE_NUM_HANDLERS,
			    STACK_SIZE);
static struct k_thread tcp4_handler_thread[CONFIG_NET_SAMPLE_NUM_HANDLERS];
static k_tid_t tcp4_handler_tid[CONFIG_NET_SAMPLE_NUM_HANDLERS];
static bool tcp4_handler_in_use[CONFIG_NET_SAMPLE_NUM_HANDLERS];
#endif

#if defined(CONFIG_NET_IPV6)
K_THREAD_STACK_ARRAY_DEFINE(tcp6_handler_stack, CONFIG_NET_SAMPLE_NUM_HANDLERS,
			    STACK_SIZE);
static struct k_thread tcp6_handler_thread[CONFIG_NET_SAMPLE_NUM_HANDLERS];
static k_tid_t tcp6_handler_tid[CONFIG_NET_SAMPLE_NUM_HANDLERS];
static bool tcp6_handler_in_use[CONFIG_NET_SAMPLE_NUM_HANDLERS];
#endif

#if defined(CONFIG_NET_SAMPLE_ASYNC_SOCKETS_POLL)
#define NUM_FDS (MAX_CLIENT_QUEUE + 2)
struct pollfd pollfds[NUM_FDS];
int pollnum;
#endif

#if defined(CONFIG_NET_SAMPLE_SYNC_SOCKETS)
static void process_tcp4(void);
static void process_tcp6(void);

K_THREAD_DEFINE(tcp4_thread_id, STACK_SIZE,
		process_tcp4, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);

K_THREAD_DEFINE(tcp6_thread_id, STACK_SIZE,
		process_tcp6, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);
#elif defined(CONFIG_NET_SAMPLE_ASYNC_SOCKETS_POLL)
static void process_async(void);

K_THREAD_DEFINE(async_thread_id, STACK_SIZE,
		process_async, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);
#endif

#if defined(CONFIG_NET_SAMPLE_ASYNC_SOCKETS_POLL)
static int setblocking(int fd, bool val)
{
	int fl, res;

	fl = fcntl(fd, F_GETFL, 0);
	if (fl == -1) {
		LOG_ERR("fcntl(F_GETFL): %d", errno);
		return -1;
	}

	if (val) {
		fl &= ~O_NONBLOCK;
	} else {
		fl |= O_NONBLOCK;
	}

	res = fcntl(fd, F_SETFL, fl);
	if (fl == -1) {
		LOG_ERR("fcntl(F_SETFL): %d", errno);
		return -1;
	}

	return 0;
}

int pollfds_add(int fd)
{
	int i;
	if (pollnum < NUM_FDS) {
		i = pollnum++;
	} else {
		for (i = 0; i < NUM_FDS; i++) {
			if (pollfds[i].fd < 0) {
				goto found;
			}
		}

		return -1;
	}

found:
	pollfds[i].fd = fd;
	pollfds[i].events = POLLIN;

	return 0;
}

void pollfds_del(int fd)
{
	for (int i = 0; i < pollnum; i++) {
		if (pollfds[i].fd == fd) {
			pollfds[i].fd = -1;
			break;
		}
	}
}
#endif

static ssize_t sendall(int sock, const void *buf, size_t len)
{
	while (len) {
		ssize_t out_len = send(sock, buf, len, 0);

		if (out_len < 0) {
			return out_len;
		}
		buf = (const char *)buf + out_len;
		len -= out_len;
	}

	return 0;
}

static int start_tcp_proto(struct data *data,
			   struct sockaddr *bind_addr,
			   socklen_t bind_addrlen)
{
	int ret;

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	data->tcp.sock = socket(bind_addr->sa_family, SOCK_STREAM,
				IPPROTO_TLS_1_2);
#else
	data->tcp.sock = socket(bind_addr->sa_family, SOCK_STREAM,
				IPPROTO_TCP);
#endif
	if (data->tcp.sock < 0) {
		LOG_ERR("Failed to create TCP socket (%s): %d", data->proto,
			errno);
		return -errno;
	}

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	sec_tag_t sec_tag_list[] = {
		SERVER_CERTIFICATE_TAG,
#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
		PSK_TAG,
#endif
	};

	ret = setsockopt(data->tcp.sock, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_list, sizeof(sec_tag_list));
	if (ret < 0) {
		LOG_ERR("Failed to set TCP secure option (%s): %d", data->proto,
			errno);
		ret = -errno;
	}
#endif

	ret = bind(data->tcp.sock, bind_addr, bind_addrlen);
	if (ret < 0) {
		LOG_ERR("Failed to bind TCP socket (%s): %d", data->proto,
			errno);
		return -errno;
	}

	ret = listen(data->tcp.sock, MAX_CLIENT_QUEUE);
	if (ret < 0) {
		LOG_ERR("Failed to listen on TCP socket (%s): %d",
			data->proto, errno);
		ret = -errno;
	}

#if defined(CONFIG_NET_SAMPLE_ASYNC_SOCKETS_POLL)
	ret = setblocking(data->tcp.sock, true);
	if (ret < 0) {
		LOG_ERR("Failed to set TCP socket as non-blocking (%d)", ret);
		ret = -errno;
	}

	ret = pollfds_add(data->tcp.sock);
	if (ret < 0) {
		LOG_ERR("Cannot add TCP socket to FD list");
		ret = -ENOMEM;
	}
#endif

	LOG_INF("Waiting for TCP connection on port %d (%s)...",
		MY_PORT, data->proto);

	return ret;
}

static int handle_data(int sock, char *buff, size_t size, int *offset)
{
	int received;

	received = recv(sock, buff, size, 0);
	if (received == 0) {
		/* Connection closed */
		LOG_INF("TCP (%s): Connection closed", data->proto);
		return 0;
	} else if (received < 0) {
		/* Socket error */
		LOG_ERR("TCP (%s): Connection error %d", data->proto,
			errno);
		return -errno;
	}

	offset += received;

#if !defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	/* To prevent fragmentation of the response, reply only if
	 * buffer is full or there is no more data to read
	 */
	if (offset == size ||
	    (recv(client, buff + offset, size - offset,
		  MSG_PEEK | MSG_DONTWAIT) < 0 &&
	     (errno == EAGAIN || errno == EWOULDBLOCK))) {
#endif
		ret = sendall(client, buff, offset);
		if (ret < 0) {
			LOG_ERR("TCP (%s): Failed to send, "
				"closing socket", data->proto);
			return 0;
		}

		LOG_DBG("TCP (%s): Received and replied with %d bytes",
			data->proto, offset);

		if (++data->tcp.accepted[slot].counter % 1000 == 0U) {
			LOG_INF("%s TCP: Sent %u packets", data->proto,
				data->tcp.accepted[slot].counter);
		}

		offset = 0;
#if !defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	}
#endif

	return 0;
}

static void handle_data_thread(void *ptr1, void *ptr2, void *ptr3)
{
	int slot = POINTER_TO_INT(ptr1);
	struct data *data = ptr2;
	bool *in_use = ptr3;
	char *buff;
	int offset = 0;
	int client;
	int ret;

	client = data->tcp.accepted[slot].sock;

	do {
		buff = data->tcp.accepted[slot].recv_buffer + offset;
		ret = handle_data(client, buff,
				  sizeof(data->tcp.accepted[slot].recv_buffer),
				  &offset);
		if (ret < 0) {
			LOG_ERR("Cannot handle data %d", ret);
			break;
		}
	} while (true);

	*in_use = false;

	(void)close(client);

	data->tcp.accepted[slot].sock = -1;
}

static int get_free_slot(struct data *data)
{
	int i;

	for (i = 0; i < CONFIG_NET_SAMPLE_NUM_HANDLERS; i++) {
		if (data->tcp.accepted[i].sock < 0) {
			return i;
		}
	}

	return -1;
}

static int process_tcp(struct data *data)
{
	int client;
	int slot;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	client = accept(data->tcp.sock, (struct sockaddr *)&client_addr,
			&client_addr_len);
	if (client < 0) {
		LOG_ERR("%s accept error (%d)", data->proto, -errno);
		return 0;
	}

	slot = get_free_slot(data);
	if (slot < 0) {
		LOG_ERR("Cannot accept more connections");
		close(client);
		return 0;
	}

	data->tcp.accepted[slot].sock = client;

	LOG_INF("TCP (%s): Accepted connection", data->proto);

#if defined(CONFIG_NET_SAMPLE_SYNC_SOCKETS)
#if defined(CONFIG_NET_IPV6)
	if (client_addr.sin_family == AF_INET6) {
		tcp6_handler_in_use[slot] = true;

		tcp6_handler_tid[slot] = k_thread_create(
			&tcp6_handler_thread[slot],
			tcp6_handler_stack[slot],
			K_THREAD_STACK_SIZEOF(tcp6_handler_stack[slot]),
			(k_thread_entry_t)handle_data,
			INT_TO_POINTER(slot), data, &tcp6_handler_in_use[slot],
			THREAD_PRIORITY,
			0, K_NO_WAIT);
	}
#endif

#if defined(CONFIG_NET_IPV4)
	if (client_addr.sin_family == AF_INET) {
		tcp4_handler_in_use[slot] = true;

		tcp4_handler_tid[slot] = k_thread_create(
			&tcp4_handler_thread[slot],
			tcp4_handler_stack[slot],
			K_THREAD_STACK_SIZEOF(tcp4_handler_stack[slot]),
			(k_thread_entry_t)handle_data,
			INT_TO_POINTER(slot), data, &tcp4_handler_in_use[slot],
			THREAD_PRIORITY,
			0, K_NO_WAIT);
	}
#endif

#endif

	return slot;
}

#if defined(CONFIG_NET_SAMPLE_ASYNC_SOCKETS_POLL)
static void process_async(void)
{
	int ret = 0;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	int num_servs = 0;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_len = sizeof(client_addr);

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		(void)memset(&addr4, 0, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(MY_PORT);

		ret = start_tcp_proto(&conf.ipv4, (struct sockaddr *)&addr4,
				      sizeof(addr4));
		if (ret < 0) {
			quit();
			return;
		}

		num_servs++;
	}

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		(void)memset(&addr6, 0, sizeof(addr6));
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(MY_PORT);

		ret = start_tcp_proto(&conf.ipv6, (struct sockaddr *)&addr6,
				      sizeof(addr6));

		num_servs++;
	}

	while (ret == 0) {
		ret = poll(pollfds, pollnum, -1);
		if (ret == -1) {
			LOG_ERR("poll error: %d", errno);
			break;
		}

		for (int i = 0; i < pollnum; i++) {
			if (!(pollfds[i].revents & POLLIN)) {
				continue;
			}

			int fd = pollfds[i].fd;
			if (i < num_servs) {
				int client = accept(fd, (struct sockaddr *)&client_addr,
						    &client_addr_len);
				if (client < 0) {
					LOG_ERR("Cannot accept client %d", errno);
					continue;
				}

				if (pollfds_add(client) < 0) {
					LOG_WRN("Too many clients connected");
					close(client);
				} else {
					setblocking(client, false);
				}
			} else {




			}
		}
	}
}
#endif

#if defined(CONFIG_NET_SAMPLE_SYNC_SOCKETS)
static void process_tcp4(void)
{
	int ret;
	struct sockaddr_in addr4;

	(void)memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(MY_PORT);

	ret = start_tcp_proto(&conf.ipv4, (struct sockaddr *)&addr4,
			      sizeof(addr4));
	if (ret < 0) {
		quit();
		return;
	}

	while (ret == 0) {
		ret = process_tcp(&conf.ipv4);
		if (ret < 0) {
			break;
		}
	}

	quit();
}

static void process_tcp6(void)
{
	int ret;
	struct sockaddr_in6 addr6;

	(void)memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(MY_PORT);

	ret = start_tcp_proto(&conf.ipv6, (struct sockaddr *)&addr6,
			      sizeof(addr6));
	if (ret < 0) {
		quit();
		return;
	}

	while (ret == 0) {
		ret = process_tcp(&conf.ipv6);
		if (ret != 0) {
			break;
		}
	}

	quit();
}
#endif

void start_tcp(void)
{
	int i;

#if defined(CONFIG_NET_SAMPLE_SYNC_SOCKETS)
	for (i = 0; i < CONFIG_NET_SAMPLE_NUM_HANDLERS; i++) {
		conf.ipv6.tcp.accepted[i].sock = -1;
		conf.ipv4.tcp.accepted[i].sock = -1;

#if defined(CONFIG_NET_IPV4)
		tcp4_handler_in_use[i] = false;
#endif
#if defined(CONFIG_NET_IPV6)
		tcp6_handler_in_use[i] = false;
#endif
	}

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		k_thread_start(tcp6_thread_id);
	}

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		k_thread_start(tcp4_thread_id);
	}
#else
	k_thread_start(async_thread_id);
#endif
}

void stop_tcp(void)
{
	int i;

	/* Not very graceful way to close a thread, but as we may be blocked
	 * in accept or recv call it seems to be necessary
	 */

#if defined(CONFIG_NET_SAMPLE_SYNC_SOCKETS)
	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		k_thread_abort(tcp6_thread_id);
		if (conf.ipv6.tcp.sock >= 0) {
			(void)close(conf.ipv6.tcp.sock);
		}

		for (i = 0; i < CONFIG_NET_SAMPLE_NUM_HANDLERS; i++) {
#if defined(CONFIG_NET_IPV6)
			if (tcp6_handler_in_use[i] == true) {
				k_thread_abort(tcp6_handler_tid[i]);
			}
#endif
			if (conf.ipv6.tcp.accepted[i].sock >= 0) {
				(void)close(conf.ipv6.tcp.accepted[i].sock);
			}
		}
	}

	if (IS_ENABLED(CONFIG_NET_IPV4)) {
		k_thread_abort(tcp4_thread_id);
		if (conf.ipv4.tcp.sock >= 0) {
			(void)close(conf.ipv4.tcp.sock);
		}

		for (i = 0; i < CONFIG_NET_SAMPLE_NUM_HANDLERS; i++) {
#if defined(CONFIG_NET_IPV4)
			if (tcp4_handler_in_use[i] == true) {
				k_thread_abort(tcp4_handler_tid[i]);
			}
#endif
			if (conf.ipv4.tcp.accepted[i].sock >= 0) {
				(void)close(conf.ipv4.tcp.accepted[i].sock);
			}
		}
	}
#else
	k_thread_abort(async_thread_id);
#endif
}
