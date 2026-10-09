/*
 * The C side of the DPDK path (#261): DPDK's fast-path functions
 * (rte_eth_rx_burst, rte_pktmbuf_*) are static inline in its headers, so Rust
 * reaches them through these small wrappers. Nothing here keeps state or
 * parses packets (that is Rust, src/packet.rs); keep it that way.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_version.h>

int rp_eal_init(int argc, char **argv) {
	int n = rte_eal_init(argc, argv);
	return n < 0 ? -rte_errno : n;
}

int rp_eal_cleanup(void) { return rte_eal_cleanup(); }

const char *rp_strerror(int e) { return rte_strerror(e); }

const char *rp_version(void) { return rte_version(); }

struct rte_mempool *rp_pool_create(const char *name, unsigned n, unsigned cache, int *err) {
	struct rte_mempool *p = rte_pktmbuf_pool_create(name, n, cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, (int)rte_socket_id());
	if (p == NULL) {
		*err = rte_errno;
	}
	return p;
}

int rp_port_by_name(const char *name, uint16_t *port) { return rte_eth_dev_get_port_by_name(name, port); }

int rp_port_driver(uint16_t port, char *buf, size_t len) {
	struct rte_eth_dev_info info;
	int r = rte_eth_dev_info_get(port, &info);
	if (r != 0) {
		return r;
	}
	snprintf(buf, len, "%s", info.driver_name ? info.driver_name : "");
	return 0;
}

/* Configures and starts a port: queues, descriptors, RSS over IP and UDP
 * ports when there are several RX queues, promiscuous off. On failure, what
 * failed goes to `err`. */
int rp_port_setup(uint16_t port, struct rte_mempool *pool, uint16_t rxq, uint16_t txq, uint16_t rxd, uint16_t txd, char *err, size_t errlen) {
	struct rte_eth_dev_info info;
	struct rte_eth_conf conf;
	int r;
	uint16_t q;

	memset(&conf, 0, sizeof(conf));
	r = rte_eth_dev_info_get(port, &info);
	if (r != 0) {
		snprintf(err, errlen, "rte_eth_dev_info_get: %s", rte_strerror(-r));
		return r;
	}
	if (rxq > info.max_rx_queues || txq > info.max_tx_queues) {
		snprintf(err, errlen, "the device has at most %u RX / %u TX queues", info.max_rx_queues, info.max_tx_queues);
		return -EINVAL;
	}
	if (rxq > 1) {
		conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		conf.rx_adv_conf.rss_conf.rss_hf = (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP) & info.flow_type_rss_offloads;
	}
	r = rte_eth_dev_configure(port, rxq, txq, &conf);
	if (r != 0) {
		snprintf(err, errlen, "rte_eth_dev_configure: %s", rte_strerror(-r));
		return r;
	}
	r = rte_eth_dev_adjust_nb_rx_tx_desc(port, &rxd, &txd);
	if (r != 0) {
		snprintf(err, errlen, "rte_eth_dev_adjust_nb_rx_tx_desc: %s", rte_strerror(-r));
		return r;
	}
	for (q = 0; q < rxq; q++) {
		r = rte_eth_rx_queue_setup(port, q, rxd, rte_eth_dev_socket_id(port), NULL, pool);
		if (r != 0) {
			snprintf(err, errlen, "rte_eth_rx_queue_setup(%u): %s", q, rte_strerror(-r));
			return r;
		}
	}
	for (q = 0; q < txq; q++) {
		r = rte_eth_tx_queue_setup(port, q, txd, rte_eth_dev_socket_id(port), NULL);
		if (r != 0) {
			snprintf(err, errlen, "rte_eth_tx_queue_setup(%u): %s", q, rte_strerror(-r));
			return r;
		}
	}
	r = rte_eth_dev_start(port);
	if (r != 0) {
		snprintf(err, errlen, "rte_eth_dev_start: %s", rte_strerror(-r));
		return r;
	}
	/* frames to other MACs are not ours (not all PMDs support this: best effort) */
	rte_eth_promiscuous_disable(port);
	return 0;
}

int rp_port_mac(uint16_t port, uint8_t mac[6]) {
	struct rte_ether_addr a;
	int r = rte_eth_macaddr_get(port, &a);
	if (r == 0) {
		memcpy(mac, a.addr_bytes, 6);
	}
	return r;
}

/* 1: link up, 0: down, < 0: error. */
int rp_port_link(uint16_t port, uint32_t *speed_mbps) {
	struct rte_eth_link link;
	int r;
	memset(&link, 0, sizeof(link));
	r = rte_eth_link_get_nowait(port, &link);
	if (r != 0) {
		return r;
	}
	*speed_mbps = link.link_speed;
	return link.link_status == RTE_ETH_LINK_UP ? 1 : 0;
}

int rp_port_stop(uint16_t port) {
	int r = rte_eth_dev_stop(port);
	rte_eth_dev_close(port);
	return r;
}

uint16_t rp_rx(uint16_t port, uint16_t q, struct rte_mbuf **pkts, uint16_t n) { return rte_eth_rx_burst(port, q, pkts, n); }

uint16_t rp_tx(uint16_t port, uint16_t q, struct rte_mbuf **pkts, uint16_t n) { return rte_eth_tx_burst(port, q, pkts, n); }

/* The data of a one-segment mbuf (NULL for chained mbufs, which are not handled). */
uint8_t *rp_data(struct rte_mbuf *m, uint16_t *len) {
	if (m->nb_segs != 1) {
		return NULL;
	}
	*len = m->data_len;
	return rte_pktmbuf_mtod(m, uint8_t *);
}

/* A new mbuf holding a copy of `data`; NULL when the pool is empty or it does not fit. */
struct rte_mbuf *rp_copy(struct rte_mempool *pool, const uint8_t *data, uint16_t len) {
	struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
	char *p;
	if (m == NULL) {
		return NULL;
	}
	p = rte_pktmbuf_append(m, len);
	if (p == NULL) {
		rte_pktmbuf_free(m);
		return NULL;
	}
	memcpy(p, data, len);
	return m;
}

void rp_free(struct rte_mbuf *m) { rte_pktmbuf_free(m); }

void rp_free_bulk(struct rte_mbuf **m, unsigned n) { rte_pktmbuf_free_bulk(m, n); }

unsigned rp_lcore_id(void) { return rte_lcore_id(); }

unsigned rp_main_lcore(void) { return rte_get_main_lcore(); }

/* The worker lcores after `prev` (RTE_MAX_LCORE when there are no more). */
unsigned rp_next_worker(unsigned prev) { return rte_get_next_lcore(prev, 1, 0); }

unsigned rp_max_lcore(void) { return RTE_MAX_LCORE; }

int rp_launch(int (*f)(void *), void *arg, unsigned lcore) { return rte_eal_remote_launch(f, arg, lcore); }

int rp_wait(unsigned lcore) { return rte_eal_wait_lcore(lcore); }
