/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_routing_sample, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <errno.h>

#include <device.h>
#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/net_if.h>

#define FIRST_IFACE	"zeth1"
#define SECOND_IFACE	"zeth2"
#define SECOND_ADDR	"2001:db8:200::1"

static struct net_if *get_iface(const char *name)
{
	struct net_if *iface;
	struct device *dev;

	dev = device_get_binding(name);
	if (!dev) {
		LOG_ERR("Cannot find iface device %s", name);
		return NULL;
	}

	iface = net_if_lookup_by_dev(dev);
	if (!iface) {
		LOG_ERR("Cannot find %s interface", name);
		return NULL;
	}

	return iface;
}

static int set_prefix(const char *dev, const char *prefix, int len)
{
	struct in6_addr addr;
	struct net_if *iface;
	struct net_if_ipv6_prefix *prefix_if;

	/* TODO IPv4 ? */
	if (net_addr_pton(AF_INET6, prefix, &addr)) {
		LOG_ERR("Invalid prefix: %s", prefix);
		return -EINVAL;
	}

	iface = get_iface(dev);
	if (!iface) {
		return -ENODEV;
	}

	prefix_if = net_if_ipv6_prefix_add(iface, &addr, len, 0);
	if (!prefix_if) {
		LOG_ERR("Cannot add %s/%d prefix", prefix, len);
		return -EINVAL;
	}

	return 0;
}

void main(void)
{
	struct in6_addr addr;
	struct net_if *iface;
	struct net_if_addr *ifaddr;
	struct net_if_ipv6_prefix *prefix;
	int err;

	LOG_INF("Start application");

	if (net_addr_pton(AF_INET6, SECOND_ADDR, &addr)) {
		LOG_ERR("Invalid address: %s", SECOND_ADDR);
		return;
	}

	iface = get_iface(SECOND_IFACE);
	if (!iface) {
		return;
	}

	ifaddr = net_if_ipv6_addr_add(iface, &addr, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		LOG_ERR("Cannot add %s to interface", SECOND_ADDR);
		return;
	}

	err = set_prefix(CONFIG_NET_SAMPLE_IFACE1_DEV,
			 CONFIG_NET_SAMPLE_IFACE1_PREFIX,
			 CONFIG_NET_SAMPLE_IFACE1_PREFIX_LEN);
	if (err) {
		LOG_ERR("Cannot add %s/%d prefix",
			CONFIG_NET_SAMPLE_IFACE1_PREFIX,
			CONFIG_NET_SAMPLE_IFACE1_PREFIX_LEN);
		return;
	}

	err = set_prefix(CONFIG_NET_SAMPLE_IFACE2_DEV,
			 CONFIG_NET_SAMPLE_IFACE2_PREFIX,
			 CONFIG_NET_SAMPLE_IFACE2_PREFIX_LEN);
	if (err) {
		LOG_ERR("Cannot add %s/%d prefix",
			CONFIG_NET_SAMPLE_IFACE2_PREFIX,
			CONFIG_NET_SAMPLE_IFACE2_PREFIX_LEN);
		return;
	}

}
