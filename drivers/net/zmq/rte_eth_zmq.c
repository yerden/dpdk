/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2024 Yerden Zhumabekov
 *  All rights reserved.
 */

#include <stdlib.h>
#include <strings.h>
#include <math.h>
#include <zmq.h>

#include <ethdev_vdev.h>
#include <rte_kvargs.h>
#include <rte_service.h>
#include <rte_ip.h>
#include <rte_net.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <rte_thash.h>
#include <rte_service_component.h>

/*
 * Specify ZMQ method to either "connect" or "bind". Default is "connect".
 */
#define ETH_ZMQ_METHOD_ARG                 "method"

/* Specify ZMQ endpoint address. */
#define ETH_ZMQ_ENDPOINT_ARG               "endpoint"

/*
 * Specify socket type here. Possible values are "pub" or "sub".
 *
 * Specifying "pub" allows to do TX on this device and forbids doing RX. On the
 * opposite specifying "sub" allows to do RX on this device and forbids doing
 * TX.
 */
#define ETH_ZMQ_SOCKET_TYPE_ARG            "type"

/* Specify packet ring size for each rx queue. */
#define ETH_ZMQ_RX_RING_SIZE_ARG           "rx_ring_size"

/* Specify packet ring size for tx queues. */
#define ETH_ZMQ_TX_RING_SIZE_ARG           "tx_ring_size"

/* Specify lcore id for poll service to run on 
 * 
 * Poll service must not be run on the same core as rx queue
 */
#define ETH_ZMQ_RX_LCORE_ID_ARG    "rx_lcore_id"
#define ETH_ZMQ_TX_LCORE_ID_ARG    "tx_lcore_id"

static const char *valid_arguments[] = {
	ETH_ZMQ_METHOD_ARG,
	ETH_ZMQ_SOCKET_TYPE_ARG,
	ETH_ZMQ_ENDPOINT_ARG,
	ETH_ZMQ_RX_RING_SIZE_ARG,
	ETH_ZMQ_TX_RING_SIZE_ARG,
	ETH_ZMQ_RX_LCORE_ID_ARG,
	ETH_ZMQ_TX_LCORE_ID_ARG,
	NULL
};

#define RSS_KEY_SIZE                       40
#define RSS_TABLE_SIZE                     (1 << 7)

static const uint8_t default_rss_key[] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

struct pmd_internals;

struct queue_stat {
	volatile unsigned long pkts;
	volatile unsigned long bytes;
	volatile unsigned long err_pkts;
	volatile unsigned long rx_nombuf;
};

struct zmq_rx_queue {
	struct pmd_internals *internals;

	void *socket;
	zmq_msg_t msg;

	struct rte_ring *ring;
	struct rte_mempool *mb_pool;
	struct queue_stat stat;
};

struct zmq_tx_queue {
	struct pmd_internals *internals;

	struct rte_ring* tx_ring;
	struct queue_stat stat;
};

struct raw_zmq_packet {
	zmq_msg_t msg;
	char *data;
	size_t len;
};

/* an alias for zmq_bind or zmq_connect */
typedef int (attach_fn)(void *socket, const char *addr);

struct pmd_options {
	int do_rx; /* if sub */
	int do_tx; /* if pub */
	int socket_type;
	void *socket;
	unsigned int rx_ring_size;
	unsigned int tx_ring_size;
	unsigned int rx_lcore_id;
	unsigned int tx_lcore_id;

	attach_fn *attach;
};

struct pmd_internals {
	uint16_t port_id;

	/* ZMQ objects */
	void *ctx;
	void *socket;
	int socket_type;
	uint32_t poll_service_id;
	uint32_t rx_lcore_id;
	uint32_t tx_lcore_id;

	uint8_t rss_key_be[RSS_KEY_SIZE];

	/* zmq SUB socket. */
	struct zmq_rx_queue rx[RTE_MAX_QUEUES_PER_PORT];
	unsigned int rx_ring_size;
	uint16_t rx_reta[128];

	/* zmq PUB socket. */
	struct zmq_tx_queue tx[RTE_MAX_QUEUES_PER_PORT];
	unsigned int tx_ring_size;
	struct rte_ring *tx_ring;

	struct rte_ether_addr eth_addr;

	uint64_t tx_offloads;
};

static struct rte_eth_link pmd_link = {
	.link_speed = RTE_ETH_SPEED_NUM_10G,
	.link_duplex = RTE_ETH_LINK_FULL_DUPLEX,
	.link_status = RTE_ETH_LINK_DOWN,
	.link_autoneg = RTE_ETH_LINK_FIXED,
};

RTE_LOG_REGISTER_DEFAULT(eth_zmq_logtype, DEBUG);

#define PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, eth_zmq_logtype, \
		"%s(): " fmt "\n", __func__, ##args)

static inline void
incr_cnt(volatile unsigned long *p, unsigned long delta)
{
	__atomic_fetch_add(p, delta, __ATOMIC_SEQ_CST);
}

static inline void
incr_cnt_one(volatile unsigned long *p)
{
	incr_cnt(p, 1);
}

static uint16_t
eth_zmq_no_rx(void *q __rte_unused, struct rte_mbuf **bufs __rte_unused,
              uint16_t nb_bufs __rte_unused)
{
	return 0;
}

/* borrowed from pcap pmd */
static int
eth_zmq_rx_jumbo(struct rte_mempool *mb_pool, struct rte_mbuf *mbuf,
                 const u_char *data, uint16_t data_len)
{
	/* Copy the first segment. */
	uint16_t len = rte_pktmbuf_tailroom(mbuf);
	struct rte_mbuf *m = mbuf;

	rte_memcpy(rte_pktmbuf_append(mbuf, len), data, len);
	data_len -= len;
	data += len;

	while (data_len > 0) {
		/* Allocate next mbuf and point to that. */
		m->next = rte_pktmbuf_alloc(mb_pool);

		if (unlikely(!m->next))
			return -1;

		m = m->next;

		/* Headroom is not needed in chained mbufs. */
		rte_pktmbuf_prepend(m, rte_pktmbuf_headroom(m));
		m->pkt_len = 0;
		m->data_len = 0;

		/* Copy next segment. */
		len = RTE_MIN(rte_pktmbuf_tailroom(m), data_len);
		rte_memcpy(rte_pktmbuf_append(m, len), data, len);

		mbuf->nb_segs++;
		data_len -= len;
		data += len;
	}

	return mbuf->nb_segs;
}

static int
msg_recv_nonempty(zmq_msg_t *msg, void *socket, int flags)
{
	int rc = 0;

	while (rc == 0)
		/*
		 * Discard empty messages and repeat receive operation.
		 *
		 * This also may be used to warm up ZMQ connection prior to
		 * streaming "real" packets.
		 */
		rc = zmq_msg_recv(msg, socket, flags);

	return rc;
}

static uint16_t
eth_zmq_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	unsigned int i;
	struct rte_mbuf *m;
	struct zmq_rx_queue *h = queue;
	uint16_t num_rx = 0;
	uint32_t rx_bytes = 0;
	int res;

	if ((h == NULL) || (bufs == NULL) || (nb_pkts == 0))
		return 0;

	uint16_t port = h->internals->port_id;
	for (i = 0; i < nb_pkts; i++) {
		if ((m = rte_pktmbuf_alloc(h->mb_pool)) == NULL) {
			incr_cnt_one(&h->stat.rx_nombuf);
			break;
		}

		struct raw_zmq_packet *raw_packet;
		res = rte_ring_sc_dequeue(h->ring, (void **)&raw_packet);

		if (res == -ENOENT) {
			rte_pktmbuf_free(m);
			break;
		}

		if (raw_packet->len <= rte_pktmbuf_tailroom(m)) {
			/* packet will fit in the mbuf, can copy it */
			rte_memcpy(rte_pktmbuf_mtod(m, void *),
			           (void *)raw_packet->data,
			           raw_packet->len);
			m->data_len = (uint16_t)raw_packet->len;
		} else {
			/* Try read jumbo frame into multi mbufs. */
			if (unlikely(eth_zmq_rx_jumbo(h->mb_pool, m, (void *)raw_packet->data, raw_packet->len) == -1)) {
				incr_cnt_one(&h->stat.rx_nombuf);
				rte_pktmbuf_free(m);
				zmq_msg_close(&raw_packet->msg);
				rte_free(raw_packet);
				break;
			}
		}

		zmq_msg_close(&raw_packet->msg);
		m->pkt_len = (uint16_t)raw_packet->len;
		m->port = port;
		bufs[num_rx] = m;
		num_rx++;
		rx_bytes += raw_packet->len;
		rte_free(raw_packet);
	}

	incr_cnt(&h->stat.pkts, num_rx);
	incr_cnt(&h->stat.bytes, rx_bytes);

	if (num_rx != 0) {
		PMD_LOG(DEBUG, "Rx burst of %d packets", num_rx);
	}
	return num_rx;
}

#define BUF_SIZE (1U<<16)

static uint16_t
eth_zmq_sink_tx(void *q, struct rte_mbuf **bufs, uint16_t nb_bufs)
{
	int i;
	struct zmq_tx_queue *h = q;

	if ((q == NULL) || (bufs == NULL))
		return 0;

	for (i = 0; i < nb_bufs; i++)
		rte_pktmbuf_free(bufs[i]);

	incr_cnt(&h->stat.pkts, i);

	return i;
}

/*
 * Callback to handle sending packets through a real NIC.
 */
static uint16_t
eth_zmq_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct zmq_tx_queue *h = queue;
	struct rte_mbuf *m;
	int ret;
	int i;
	uint16_t num_tx = 0;
	uint32_t tx_bytes = 0;

	if ((h == NULL) || (bufs == NULL) || (nb_pkts == 0))
		return 0;

	unsigned char temp_data[BUF_SIZE];
	size_t len;

	for (i = 0; i < nb_pkts; i++) {
		m = bufs[i];
		len = rte_pktmbuf_pkt_len(m);
		if (unlikely(!rte_pktmbuf_is_contiguous(m) &&
				len > sizeof(temp_data))) {
			PMD_LOG(ERR,
			        "Dropping multi segment packet. Size (%zd) > max size (%zd).",
			        len, sizeof(temp_data));
			rte_pktmbuf_free(m);
			continue;
		}

		if ((ret = rte_ring_mp_enqueue(h->internals->tx_ring, m)) == -ENOBUFS) {
			PMD_LOG(ERR, "Packet enqueue failed not enough room(%d)", ret);
			break;
		}

		num_tx++;
		tx_bytes += len;
	}

	incr_cnt(&h->stat.pkts, num_tx);
	incr_cnt(&h->stat.bytes, tx_bytes);
	incr_cnt(&h->stat.err_pkts, i - num_tx);

	return i;
}

static int
eth_dev_start(struct rte_eth_dev *dev)
{
	struct rte_eth_rss_conf rss_conf;
	struct pmd_internals *internals = dev->data->dev_private;
	uint16_t i;

	if (dev == NULL)
		return -EINVAL;

	dev->data->dev_link.link_status = RTE_ETH_LINK_UP;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STARTED;

	rss_conf = dev->data->dev_conf.rx_adv_conf.rss_conf;

	const uint8_t *rss_key = rss_conf.rss_key ? rss_conf.rss_key : default_rss_key;
	rte_convert_rss_key((const uint32_t *)rss_key,
	                    (uint32_t *)internals->rss_key_be,
	                    RTE_DIM(default_rss_key));

	PMD_LOG(DEBUG, "Successfully configured rss default rss key used: %d", rss_conf.rss_key == NULL);

	return 0;
}

static int
eth_dev_stop(struct rte_eth_dev *dev)
{
	uint16_t i;

	if (dev == NULL)
		return 0;

	dev->data->dev_link.link_status = RTE_ETH_LINK_DOWN;

	for (i = 0; i < dev->data->nb_rx_queues; i++)
		dev->data->rx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;
	for (i = 0; i < dev->data->nb_tx_queues; i++)
		dev->data->tx_queue_state[i] = RTE_ETH_QUEUE_STATE_STOPPED;

	return 0;
}

static int
eth_dev_close(struct rte_eth_dev *dev)
{
	PMD_LOG(INFO, "Closing zmq ethdev on NUMA socket %u",
	        rte_socket_id());

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	/* mac_addrs must not be freed alone because part of dev_private */
	dev->data->mac_addrs = NULL;

	return 0;
}

static uint32_t
softrss_be(rte_be16_t ether_type, void *header, const uint8_t *rss_key_be)
{
	uint32_t input_len;
	uint32_t rss = 0;

	switch (rte_be_to_cpu_16(ether_type)) {
	case RTE_ETHER_TYPE_IPV4:
		struct rte_ipv4_tuple ipv4_tuple;
		struct rte_ipv4_hdr *ipv4_hdr = header;

		ipv4_tuple.src_addr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
		ipv4_tuple.dst_addr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
		input_len = RTE_THASH_V4_L3_LEN;

		rss = rte_softrss_be((uint32_t *)&ipv4_tuple, input_len, rss_key_be);
		break;
	case RTE_ETHER_TYPE_IPV6:
		struct rte_ipv6_tuple ipv6_tuple;
		struct rte_ipv6_hdr *ipv6_hdr = header;

		rte_thash_load_v6_addrs(ipv6_hdr,
		                        (union rte_thash_tuple *)&ipv6_tuple);
		input_len = RTE_THASH_V6_L3_LEN;

		rss = rte_softrss_be((uint32_t *)&ipv6_tuple, input_len, rss_key_be);
		break;
	}

	return rss;
}

static int
zmq_tx_send_socket(void *args)
{
	struct rte_eth_dev *dev = args;
	struct pmd_internals *internals = dev->data->dev_private;
	struct rte_mbuf *mbuf;
	size_t len;
	int ret;

	if (internals->socket == NULL) {
		rte_delay_ms(1);
		PMD_LOG(INFO, "Service deinitialized");
		return -1;
	}

	/* Main loop */
	while (1) {
		char temp_data[BUF_SIZE];

		if ((ret = rte_ring_mc_dequeue(internals->tx_ring, (void **)&mbuf)) == -ENOENT) {
			continue;
		}

		len = rte_pktmbuf_pkt_len(mbuf);
		if (zmq_send(internals->socket, rte_pktmbuf_read(mbuf, 0, len, temp_data), len, ZMQ_DONTWAIT) == -1) {
			PMD_LOG(ERR, "error sending ZMQ msg: %s (%d)", zmq_strerror(errno), errno);
			rte_pktmbuf_free(mbuf);
			return -1;
		}

		rte_pktmbuf_free(mbuf);
	}

	return 0;
}

static int
zmq_rx_poll_socket(void *args)
{
	struct rte_eth_dev *dev = args;
	struct pmd_internals *internals = dev->data->dev_private;

	if (internals->socket == NULL) {
		rte_delay_ms(1);
		PMD_LOG(INFO, "Service deinitialized");
		return -1;
	}

	/* Main loop */
	while (1) {
		zmq_msg_t msg;
		struct rte_mbuf mbuf;
		struct rte_net_hdr_lens hdr_lens;
		void *msg_data;
		int caplen;

		int ret = zmq_msg_init(&msg);
		if (ret == -1) {
			PMD_LOG(ERR, "Failed to init zmq message");
			return -1;
		}

		caplen = msg_recv_nonempty(&msg, internals->socket, ZMQ_DONTWAIT);
		if (caplen < 0) {
			zmq_msg_close(&msg);

			if (errno != EAGAIN) {
				PMD_LOG(ERR, "error receiving ZMQ msg: %s", zmq_strerror(errno));
				return -1;
			}

			continue;
		}

		msg_data = zmq_msg_data(&msg);

		uint16_t buf_len = RTE_ALIGN_CEIL(caplen + 1024 +
			sizeof(struct rte_mbuf_ext_shared_info), 8);
		rte_pktmbuf_attach_extbuf(&mbuf, msg_data, 0, buf_len, NULL);
		mbuf.data_len = caplen;

		uint16_t ptype = rte_net_get_ptype(&mbuf, &hdr_lens, RTE_PTYPE_ALL_MASK);
		PMD_LOG(DEBUG, "Rx Layers detected %s %s %s", rte_get_ptype_l2_name(ptype), rte_get_ptype_l3_name(ptype), rte_get_ptype_l4_name(ptype));

		struct rte_ether_hdr *eth_header = (struct rte_ether_hdr *)msg_data;

		uint32_t rss = softrss_be(eth_header->ether_type,
		                          (char *)msg_data + hdr_lens.l2_len,
		                          internals->rss_key_be);

		uint32_t bitmask = RSS_TABLE_SIZE - 1;
		uint16_t rx_index = internals->rx_reta[rss & bitmask];
		struct zmq_rx_queue *q = &internals->rx[rx_index];

		struct raw_zmq_packet *raw_packet = rte_malloc("raw_packet", sizeof(struct raw_zmq_packet), 0);
		if (raw_packet == NULL) {
			PMD_LOG(ERR, "Failed to allocate zeromq packet");
			return -ENOMEM;
		}
		raw_packet->data = msg_data;
		raw_packet->msg = msg;
		raw_packet->len = caplen;

		if ((ret = rte_ring_sp_enqueue(q->ring, raw_packet)) == -ENOBUFS) {
			PMD_LOG(ERR, "Packet enqueue failed not enough room(%d)", ret);
			return -1;
		}
	}

	return 0;
}

static int
zmq_fill_rss_table(struct rte_eth_dev *dev, size_t queue_num)
{
	struct pmd_internals *internals = dev->data->dev_private;
	size_t i;
	uint16_t val;

	for (i = 0; i < RSS_TABLE_SIZE; ++i) {
		val = (queue_num - i) % queue_num;
		if (val >= dev->data->nb_rx_queues)
			return -1;

		internals->rx_reta[i] = val;
	}
	return 0;
}

static struct rte_service_spec zmq_poll_services[2] = {
	{"zmq_rx_service", zmq_rx_poll_socket, NULL, 0, 0},
	{"zmq_tx_service", zmq_tx_send_socket, NULL, 0, 0}
};

static int
eth_dev_configure(struct rte_eth_dev *dev)
{
	uint16_t nb_rx_queues = dev->data->nb_rx_queues;
	struct pmd_internals *internals = dev->data->dev_private;
	struct rte_service_spec *zmq_poll_service;
	int ret;
	uint32_t service_id;
	unsigned int lcore_id;

	ret = zmq_fill_rss_table(dev, nb_rx_queues);
	if (ret < 0)
		PMD_LOG(ERR, "Failed to fill rss indirection table");

	if (internals->socket_type == ZMQ_PUB) {
		internals->tx_ring = rte_ring_create("tx_packet_ring",
		                                     internals->tx_ring_size,
		                                     SOCKET_ID_ANY,
		                                     RING_F_MP_RTS_ENQ|RING_F_MC_RTS_DEQ);

		lcore_id = internals->tx_lcore_id;
		zmq_poll_service = &zmq_poll_services[1];
	} else {
		lcore_id = internals->rx_lcore_id;
		zmq_poll_service = &zmq_poll_services[0];
	}
	zmq_poll_service->callback_userdata = dev;

	ret = rte_service_component_register(zmq_poll_service, &service_id);
	if (ret) {
		PMD_LOG(ERR, "Failed to start service component");
		return -1;
	}
	internals->poll_service_id = service_id;

	rte_service_component_runstate_set(service_id, 1);

	ret = rte_service_runstate_set(service_id, 1);
	if (ret)
		return -ENOEXEC;

	PMD_LOG(INFO, "Zmq poll service mapped to lcore: %d", lcore_id);

	ret = rte_service_lcore_add(lcore_id);
	if (ret && ret != -EALREADY)
		PMD_LOG(INFO, "Core %d added ret %d", lcore_id, ret);

	ret = rte_service_lcore_start(lcore_id);
	if (ret && ret != -EALREADY)
		PMD_LOG(INFO, "Core %d start ret %d", lcore_id, ret);

	if (rte_service_map_lcore_set(service_id, lcore_id, 1))
		PMD_LOG(ERR, "Failed to map lcore %d", lcore_id);


	return 0;
}

static int
eth_dev_info(struct rte_eth_dev *dev,
             struct rte_eth_dev_info *dev_info)
{
	if ((dev == NULL) || (dev_info == NULL))
		return -EINVAL;

	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = RTE_MAX_QUEUES_PER_PORT;
	dev_info->max_tx_queues = RTE_MAX_QUEUES_PER_PORT;
	dev_info->min_rx_bufsize = 0;
	dev_info->hash_key_size = RSS_KEY_SIZE;
	dev_info->flow_type_rss_offloads = RTE_ETH_RSS_IP;
	dev_info->rss_algo_capa = RTE_ETH_HASH_ALGO_CAPA_MASK(DEFAULT) |
	                          RTE_ETH_HASH_ALGO_CAPA_MASK(TOEPLITZ);

	return 0;
}

static int
eth_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
                   uint16_t nb_rx_desc __rte_unused,
                   unsigned int socket_id __rte_unused,
                   const struct rte_eth_rxconf *rx_conf __rte_unused,
                   struct rte_mempool *mb_pool)
{
	struct pmd_internals *internals;
	struct zmq_rx_queue *q;

	if ((dev == NULL) || (mb_pool == NULL))
		return -EINVAL;

	internals = dev->data->dev_private;

	if (rx_queue_id >= dev->data->nb_rx_queues)
		return -ENODEV;

	q = &internals->rx[rx_queue_id];
	q->mb_pool = mb_pool;
	q->socket = internals->socket;
	q->internals = internals;
	zmq_msg_init(&q->msg);

	char ring_name[RTE_RING_NAMESIZE];
	snprintf(ring_name, sizeof(ring_name), "rx_%d", rx_queue_id);
	q->ring = rte_ring_create(ring_name,
	                          internals->rx_ring_size,
	                          SOCKET_ID_ANY,
	                          RING_F_SP_ENQ|RING_F_SC_DEQ);

	dev->data->rx_queues[rx_queue_id] = q;
	return 0;
}

static int
eth_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
                   uint16_t nb_tx_desc __rte_unused,
                   unsigned int socket_id __rte_unused,
                   const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *internals;
	struct zmq_tx_queue *q;

	if (dev == NULL)
		return -EINVAL;

	internals = dev->data->dev_private;

	if (tx_queue_id >= dev->data->nb_tx_queues)
		return -ENODEV;

	q = &internals->tx[tx_queue_id];
	q->tx_ring = internals->tx_ring;
	q->internals = internals;

	dev->data->tx_queues[tx_queue_id] = q;
	return 0;
}

static void
eth_rx_queue_release(struct rte_eth_dev *dev, uint16_t qid)
{
	struct zmq_rx_queue *q = dev->data->rx_queues[qid];
	if (q == NULL)
		return;

	zmq_msg_close(&q->msg);
}

static int
eth_mtu_set(struct rte_eth_dev *dev __rte_unused, uint16_t mtu __rte_unused)
{
	return 0;
}

static int
eth_link_update(struct rte_eth_dev *dev __rte_unused,
                int wait_to_complete __rte_unused)
{
	return 0;
}

static int
eth_mac_address_set(__rte_unused struct rte_eth_dev *dev,
                    __rte_unused struct rte_ether_addr *addr)
{
	return 0;
}

static unsigned long
load_cnt(const volatile unsigned long *p)
{
	return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

static void
store_cnt(volatile unsigned long *p, volatile unsigned long v)
{
	__atomic_store_n(p, v, __ATOMIC_SEQ_CST);
}

static int
eth_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *igb_stats)
{
	unsigned int i, num_stats;
	unsigned long rx_total = 0, tx_total = 0;
	const struct pmd_internals *internal;

	if ((dev == NULL) || (igb_stats == NULL))
		return -EINVAL;

	internal = dev->data->dev_private;

	num_stats = RTE_MIN((unsigned int)RTE_ETHDEV_QUEUE_STAT_CNTRS,
	                    RTE_MIN(dev->data->nb_rx_queues, 
	                            RTE_DIM(internal->rx)));
	for (i = 0; i < num_stats; i++) {
		/* NOTE: review for atomic access */
		igb_stats->q_ipackets[i] = load_cnt(&internal->rx[i].stat.pkts);
		rx_total += igb_stats->q_ipackets[i];
	}

	num_stats = RTE_MIN((unsigned int)RTE_ETHDEV_QUEUE_STAT_CNTRS,
	                    RTE_MIN(dev->data->nb_tx_queues,
	                            RTE_DIM(internal->tx)));
	for (i = 0; i < num_stats; i++) {
		/* NOTE: review for atomic access */
		igb_stats->q_opackets[i] = load_cnt(&internal->tx[i].stat.pkts);
		tx_total += igb_stats->q_opackets[i];
	}

	/* TODO: add rx_nombufs, err_pkts etc */
	igb_stats->ipackets = rx_total;
	igb_stats->opackets = tx_total;

	return 0;
}

static int
eth_stats_reset(struct rte_eth_dev *dev)
{
	unsigned int i;
	struct pmd_internals *internal;

	if (dev == NULL)
		return -EINVAL;

	internal = dev->data->dev_private;
	for (i = 0; i < RTE_DIM(internal->rx); i++)
		store_cnt(&internal->rx[i].stat.pkts, 0);
	for (i = 0; i < RTE_DIM(internal->tx); i++)
		store_cnt(&internal->tx[i].stat.pkts, 0);

	return 0;
}

static const struct eth_dev_ops ops = {
	.dev_close = eth_dev_close,
	.dev_start = eth_dev_start,
	.dev_stop = eth_dev_stop,
	.dev_configure = eth_dev_configure,
	.dev_infos_get = eth_dev_info,
	.rx_queue_setup = eth_rx_queue_setup,
	.tx_queue_setup = eth_tx_queue_setup,
	.rx_queue_release = eth_rx_queue_release,
	.mtu_set = eth_mtu_set,
	.link_update = eth_link_update,
	.mac_addr_set = eth_mac_address_set,
	.stats_get = eth_stats_get,
	.stats_reset = eth_stats_reset,
};

static int
get_method(const char *key __rte_unused,
           const char *value, void *arg)
{
	struct pmd_options *opts = arg;

	if (strcasecmp(value, "connect") == 0)
		opts->attach = zmq_connect;
	else if (strcasecmp(value, "bind") == 0)
		opts->attach = zmq_bind;
	else {
		PMD_LOG(ERR, "invalid method: '%s'", value);
		return -EINVAL;
	}

	return 0;
}

static int
get_socket_type(const char *key __rte_unused,
                const char *value, void *arg)
{
	struct pmd_options *opts = arg;

	if (strcasecmp(value, "pub") == 0) {
		opts->do_rx = 0;
		opts->do_tx = 1;
		opts->socket_type = ZMQ_PUB;
	} else if (strcasecmp(value, "sub") == 0) {
		opts->do_rx = 1;
		opts->do_tx = 0;
		opts->socket_type = ZMQ_SUB;
	} else {
		PMD_LOG(ERR, "unsupported ZMQ socket type: '%s'", value);
		return -ENOTSUP;
	}

	return 0;
}

static int
get_endpoint(const char *key __rte_unused,
             const char *value, void *arg)
{
	struct pmd_options *opts = arg;
	return opts->attach(opts->socket, value);
}

static int
get_rx_ring_size(const char *key __rte_unused,
                 const char *value, void *arg)
{
	if (*value == '-') {
		PMD_LOG(ERR, "Ring size cannot be negative");
		return -EINVAL;
	}

	struct pmd_options *opts = arg;
	char *end = NULL;
	unsigned long ring_size = strtoul(value, &end, 10);

	if (end == NULL) {
		PMD_LOG(ERR, "Invalid characters in ring size %s", end);
		return -EINVAL;
	}

	if ((ring_size & (ring_size - 1)) != 0 || ring_size == 0) {
		PMD_LOG(ERR, "Ring size must be a power of 2, not zero and bigger than 0");
		return -EINVAL;
	}

	opts->rx_ring_size = ring_size;

	return 0;
}

static int
get_tx_ring_size(const char *key __rte_unused,
                 const char *value, void *arg)
{
	if (*value == '-') {
		PMD_LOG(ERR, "Ring size cannot be negative");
		return -EINVAL;
	}

	struct pmd_options *opts = arg;
	char *end = NULL;
	unsigned long ring_size = strtoul(value, &end, 10);

	if (end == NULL) {
		PMD_LOG(ERR, "Invalid characters in ring size %s", end);
		return -EINVAL;
	}

	if ((ring_size & (ring_size - 1)) != 0 || ring_size == 0) {
		PMD_LOG(ERR, "Ring size must be a power of 2, not zero and bigger than 0");
		return -EINVAL;
	}

	opts->tx_ring_size = ring_size;

	return 0;
}

static int
get_rx_lcore_id(const char *key __rte_unused,
                 const char *value, void *arg)
{
	struct pmd_options *opts = arg;
	char *end = NULL;
	unsigned int lcore_id = strtoul(value, &end, 10);

	if (end == NULL) {
		PMD_LOG(ERR, "Invalid characters in lcore_service_id %s", end);
		return -EINVAL;
	}

	if (!rte_lcore_is_enabled(lcore_id)) {
		PMD_LOG(ERR, "Lcore assigned for service: %u is not enabled", lcore_id);
		return -EINVAL;
	}

	opts->rx_lcore_id = lcore_id;

	return 0;
}

static int
get_tx_lcore_id(const char *key __rte_unused,
                 const char *value, void *arg)
{
	struct pmd_options *opts = arg;
	char *end = NULL;
	unsigned int lcore_id = strtoul(value, &end, 10);

	if (end == NULL) {
		PMD_LOG(ERR, "Invalid characters in lcore_service_id %s", end);
		return -EINVAL;
	}

	if (!rte_lcore_is_enabled(lcore_id)) {
		PMD_LOG(ERR, "Lcore assigned for service: %u is not enabled", lcore_id);
		return -EINVAL;
	}

	opts->tx_lcore_id = lcore_id;

	return 0;
}

static void
set_nb_queues(struct rte_eth_dev_data *data)
{
	struct pmd_internals *internals;

	internals = data->dev_private;

	if (internals->socket_type == ZMQ_SUB) {
		data->nb_rx_queues = 1;
		data->nb_tx_queues = RTE_DIM(internals->tx);
	}

	if (internals->socket_type == ZMQ_PUB) {
		data->nb_rx_queues = RTE_DIM(internals->rx);
		data->nb_tx_queues = 1;
	}
}

static void
set_pkt_ops(struct rte_eth_dev *eth_dev)
{
	struct pmd_internals *internals;

	internals = eth_dev->data->dev_private;

	if (internals->socket_type == ZMQ_SUB) {
		eth_dev->rx_pkt_burst = eth_zmq_rx;
		eth_dev->tx_pkt_burst = eth_zmq_sink_tx;
	}

	if (internals->socket_type == ZMQ_PUB) {
		eth_dev->rx_pkt_burst = eth_zmq_no_rx;
		eth_dev->tx_pkt_burst = eth_zmq_tx;
	}
}

static int
pmd_zmq_probe(struct rte_vdev_device *dev)
{
	if (!dev)
		return -EINVAL;

	struct pmd_options args = {
		/* By default, we do zmq_connect() */
		.attach = zmq_connect,
		.rx_ring_size = 256,
		.tx_ring_size = 256,
	};

	struct rte_kvargs *kvlist = NULL;
	struct rte_eth_dev *eth_dev;
	int ret;
	void *socket, *ctx;

	const char *name = rte_vdev_device_name(dev);
	const char *params = rte_vdev_device_args(dev);

	PMD_LOG(INFO, "Initializing pmd_zmq for %s", name);
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (!eth_dev) {
			PMD_LOG(ERR, "Failed to probe %s", name);
			return -1;
		}

		eth_dev->dev_ops = &ops;
		eth_dev->device = &dev->device;

		set_pkt_ops(eth_dev);

		rte_eth_dev_probing_finish(eth_dev);
		return 0;
	}

	if (params == NULL || *params == 0) {
		PMD_LOG(ERR, "Specify zmq parameters, at least '%s' and '%s' is required",
		        ETH_ZMQ_ENDPOINT_ARG,
		        ETH_ZMQ_SOCKET_TYPE_ARG);
		return -EINVAL;
	}

	/* create ZMQ socket */
	if ((ctx = zmq_ctx_new()) == NULL) {
		PMD_LOG(ERR, "unable to create ZMQ context: %s (%d)", zmq_strerror(errno), errno);
		return -errno;
	}

	kvlist = rte_kvargs_parse(params, valid_arguments);
	if (kvlist == NULL) {
		zmq_ctx_term(ctx);
		return -1;
	}

	/* find out what socket we need */
	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_SOCKET_TYPE_ARG,
	                         &get_socket_type, &args);
	if (ret < 0) {
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return ret;
	}

	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_METHOD_ARG,
	                         &get_method, &args);
	if (ret < 0) {
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return ret;
	}

	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_RX_RING_SIZE_ARG,
	                         &get_rx_ring_size, &args);
	if (ret < 0) {
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return ret;
	}

	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_TX_RING_SIZE_ARG,
	                         &get_tx_ring_size, &args);

	if (ret < 0) {
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return ret;
	}

	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_RX_LCORE_ID_ARG,
	                         &get_rx_lcore_id, &args);
	if (ret < 0) {
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return ret;
	}

	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_TX_LCORE_ID_ARG,
	                         &get_tx_lcore_id, &args);

	if (ret < 0) {
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return ret;
	}

	if ((socket = zmq_socket(ctx, args.socket_type)) == NULL) {
		PMD_LOG(ERR, "unable to create ZMQ socket: %s (%d)", zmq_strerror(errno), errno);
		zmq_ctx_term(ctx);
		rte_kvargs_free(kvlist);
		return -errno;
	}

	args.socket = socket;

	ret = rte_kvargs_process(kvlist,
	                         ETH_ZMQ_ENDPOINT_ARG,
	                         &get_endpoint, &args);
	/* end of use kvlist */
	rte_kvargs_free(kvlist);

	if (ret < 0) {
		PMD_LOG(ERR, "error setting up socket: %s (%d)", zmq_strerror(errno), errno);
		zmq_close(socket);
		zmq_ctx_term(ctx);
		return ret;
	}

	if (args.socket_type == ZMQ_SUB) {
		/* FIXME: maybe a filter should be explicitly specified? */
		if (zmq_setsockopt(socket, ZMQ_SUBSCRIBE, NULL, 0) == -1) {
			PMD_LOG(ERR, "unable to subscribe ZMQ socket: %s (%d)", zmq_strerror(errno), errno);
			zmq_close(socket);
			zmq_ctx_term(ctx);
			return -errno;
		}
	}

	/*
	 * XXX: starting to setup device
	 */
	if (dev->device.numa_node == SOCKET_ID_ANY)
		dev->device.numa_node = rte_socket_id();

	PMD_LOG(INFO, "Creating zmq ethdev on numa socket %u",
		dev->device.numa_node);

	struct pmd_internals *internals;
	eth_dev = rte_eth_vdev_allocate(dev, sizeof(*internals));
	if (!eth_dev) {
		zmq_close(socket);
		zmq_ctx_term(ctx);
		return -ENOMEM;
	}

	internals = eth_dev->data->dev_private;
	internals->ctx = ctx;
	internals->socket = socket;
	internals->port_id = eth_dev->data->port_id;
	internals->socket_type = args.socket_type;
	internals->rx_ring_size = args.rx_ring_size;
	internals->tx_ring_size = args.tx_ring_size;
	internals->rx_lcore_id = args.rx_lcore_id;
	internals->tx_lcore_id = args.tx_lcore_id;

	struct rte_eth_dev_data *data;
	data = eth_dev->data;

	set_nb_queues(data);
	set_pkt_ops(eth_dev);

	data->dev_link = pmd_link;
	data->mac_addrs = &internals->eth_addr;
	data->promiscuous = 1;
	data->all_multicast = 1;
	data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	rte_eth_random_addr(internals->eth_addr.addr_bytes);
	eth_dev->dev_ops = &ops;

	rte_eth_dev_probing_finish(eth_dev);
	return 0;
}

static int
pmd_zmq_remove(struct rte_vdev_device *dev)
{
	struct rte_eth_dev *eth_dev = NULL;

	if (!dev)
		return -EINVAL;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(dev));
	if (eth_dev == NULL)
		return 0; /* port already released */

	struct pmd_internals *internals = eth_dev->data->dev_private;

	if (rte_service_runstate_set(internals->poll_service_id, 0) != 0)
		PMD_LOG(ERR, "Service stop failed");

	eth_dev_close(eth_dev);

	zmq_close(internals->socket);
	zmq_ctx_term(internals->ctx);

	rte_eth_dev_release_port(eth_dev);

	return 0;
}

static struct rte_vdev_driver pmd_zmq_drv = {
	.probe = pmd_zmq_probe,
	.remove = pmd_zmq_remove,
};

RTE_PMD_REGISTER_VDEV(net_zmq, pmd_zmq_drv);
RTE_PMD_REGISTER_ALIAS(net_zmq, eth_zmq);

RTE_PMD_REGISTER_PARAM_STRING(net_zmq,
	ETH_ZMQ_METHOD_ARG"=<string> "
	ETH_ZMQ_ENDPOINT_ARG"=<string> "
	ETH_ZMQ_SOCKET_TYPE_ARG"=<string> "
	ETH_ZMQ_RX_RING_SIZE_ARG"=<int> "
	ETH_ZMQ_TX_RING_SIZE_ARG"=<int> "
	ETH_ZMQ_RX_LCORE_ID_ARG"=<int> "
	ETH_ZMQ_TX_LCORE_ID_ARG"=<int> ");
