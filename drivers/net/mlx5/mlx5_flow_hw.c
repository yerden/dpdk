/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#include <rte_flow.h>

#include <mlx5_malloc.h>
#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_rx.h"

#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)

/* The maximum actions support in the flow. */
#define MLX5_HW_MAX_ACTS 16

/* Default push burst threshold. */
#define BURST_THR 32u

/* Default queue to flush the flows. */
#define MLX5_DEFAULT_FLUSH_QUEUE 0

const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops;

/* DR action flags with different table. */
static uint32_t mlx5_hw_act_flag[MLX5_HW_ACTION_FLAG_MAX]
				[MLX5DR_TABLE_TYPE_MAX] = {
	{
		MLX5DR_ACTION_FLAG_ROOT_RX,
		MLX5DR_ACTION_FLAG_ROOT_TX,
		MLX5DR_ACTION_FLAG_ROOT_FDB,
	},
	{
		MLX5DR_ACTION_FLAG_HWS_RX,
		MLX5DR_ACTION_FLAG_HWS_TX,
		MLX5DR_ACTION_FLAG_HWS_FDB,
	},
};

/**
 * Set rxq flag.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] enable
 *   Flag to enable or not.
 */
static void
flow_hw_rxq_flag_set(struct rte_eth_dev *dev, bool enable)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	unsigned int i;

	if ((!priv->mark_enabled && !enable) ||
	    (priv->mark_enabled && enable))
		return;
	for (i = 0; i < priv->rxqs_n; ++i) {
		struct mlx5_rxq_ctrl *rxq_ctrl = mlx5_rxq_ctrl_get(dev, i);

		rxq_ctrl->rxq.mark = enable;
	}
	priv->mark_enabled = enable;
}

/**
 * Set the hash fields according to the @p rss_desc information.
 *
 * @param[in] rss_desc
 *   Pointer to the mlx5_flow_rss_desc.
 * @param[out] hash_fields
 *   Pointer to the RSS hash fields.
 */
static void
flow_hw_hashfields_set(struct mlx5_flow_rss_desc *rss_desc,
		       uint64_t *hash_fields)
{
	uint64_t fields = 0;
	int rss_inner = 0;
	uint64_t rss_types = rte_eth_rss_hf_refine(rss_desc->types);

#ifdef HAVE_IBV_DEVICE_TUNNEL_SUPPORT
	if (rss_desc->level >= 2)
		rss_inner = 1;
#endif
	if (rss_types & MLX5_IPV4_LAYER_TYPES) {
		if (rss_types & RTE_ETH_RSS_L3_SRC_ONLY)
			fields |= IBV_RX_HASH_SRC_IPV4;
		else if (rss_types & RTE_ETH_RSS_L3_DST_ONLY)
			fields |= IBV_RX_HASH_DST_IPV4;
		else
			fields |= MLX5_IPV4_IBV_RX_HASH;
	} else if (rss_types & MLX5_IPV6_LAYER_TYPES) {
		if (rss_types & RTE_ETH_RSS_L3_SRC_ONLY)
			fields |= IBV_RX_HASH_SRC_IPV6;
		else if (rss_types & RTE_ETH_RSS_L3_DST_ONLY)
			fields |= IBV_RX_HASH_DST_IPV6;
		else
			fields |= MLX5_IPV6_IBV_RX_HASH;
	}
	if (rss_types & RTE_ETH_RSS_UDP) {
		if (rss_types & RTE_ETH_RSS_L4_SRC_ONLY)
			fields |= IBV_RX_HASH_SRC_PORT_UDP;
		else if (rss_types & RTE_ETH_RSS_L4_DST_ONLY)
			fields |= IBV_RX_HASH_DST_PORT_UDP;
		else
			fields |= MLX5_UDP_IBV_RX_HASH;
	} else if (rss_types & RTE_ETH_RSS_TCP) {
		if (rss_types & RTE_ETH_RSS_L4_SRC_ONLY)
			fields |= IBV_RX_HASH_SRC_PORT_TCP;
		else if (rss_types & RTE_ETH_RSS_L4_DST_ONLY)
			fields |= IBV_RX_HASH_DST_PORT_TCP;
		else
			fields |= MLX5_TCP_IBV_RX_HASH;
	}
	if (rss_types & RTE_ETH_RSS_ESP)
		fields |= IBV_RX_HASH_IPSEC_SPI;
	if (rss_inner)
		fields |= IBV_RX_HASH_INNER;
	*hash_fields = fields;
}

/**
 * Generate the pattern item flags.
 * Will be used for shared RSS action.
 *
 * @param[in] items
 *   Pointer to the list of items.
 *
 * @return
 *   Item flags.
 */
static uint64_t
flow_hw_rss_item_flags_get(const struct rte_flow_item items[])
{
	uint64_t item_flags = 0;
	uint64_t last_item = 0;

	for (; items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
		int tunnel = !!(item_flags & MLX5_FLOW_LAYER_TUNNEL);
		int item_type = items->type;

		switch (item_type) {
		case RTE_FLOW_ITEM_TYPE_IPV4:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV4 :
					     MLX5_FLOW_LAYER_OUTER_L3_IPV4;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L3_IPV6 :
					     MLX5_FLOW_LAYER_OUTER_L3_IPV6;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L4_TCP :
					     MLX5_FLOW_LAYER_OUTER_L4_TCP;
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			last_item = tunnel ? MLX5_FLOW_LAYER_INNER_L4_UDP :
					     MLX5_FLOW_LAYER_OUTER_L4_UDP;
			break;
		case RTE_FLOW_ITEM_TYPE_GRE:
			last_item = MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_NVGRE:
			last_item = MLX5_FLOW_LAYER_GRE;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			last_item = MLX5_FLOW_LAYER_VXLAN;
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN_GPE:
			last_item = MLX5_FLOW_LAYER_VXLAN_GPE;
			break;
		case RTE_FLOW_ITEM_TYPE_GENEVE:
			last_item = MLX5_FLOW_LAYER_GENEVE;
			break;
		case RTE_FLOW_ITEM_TYPE_MPLS:
			last_item = MLX5_FLOW_LAYER_MPLS;
			break;
		case RTE_FLOW_ITEM_TYPE_GTP:
			last_item = MLX5_FLOW_LAYER_GTP;
			break;
		default:
			break;
		}
		item_flags |= last_item;
	}
	return item_flags;
}

/**
 * Register destination table DR jump action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] table_attr
 *   Pointer to the flow attributes.
 * @param[in] dest_group
 *   The destination group ID.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static struct mlx5_hw_jump_action *
flow_hw_jump_action_register(struct rte_eth_dev *dev,
			     const struct rte_flow_attr *attr,
			     uint32_t dest_group,
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_attr jattr = *attr;
	struct mlx5_flow_group *grp;
	struct mlx5_flow_cb_ctx ctx = {
		.dev = dev,
		.error = error,
		.data = &jattr,
	};
	struct mlx5_list_entry *ge;

	jattr.group = dest_group;
	ge = mlx5_hlist_register(priv->sh->flow_tbls, dest_group, &ctx);
	if (!ge)
		return NULL;
	grp = container_of(ge, struct mlx5_flow_group, entry);
	return &grp->jump;
}

/**
 * Release jump action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] jump
 *   Pointer to the jump action.
 */

static void
flow_hw_jump_release(struct rte_eth_dev *dev, struct mlx5_hw_jump_action *jump)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_flow_group *grp;

	grp = container_of
		(jump, struct mlx5_flow_group, jump);
	mlx5_hlist_unregister(priv->sh->flow_tbls, &grp->entry);
}

/**
 * Register queue/RSS action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] hws_flags
 *   DR action flags.
 * @param[in] action
 *   rte flow action.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static inline struct mlx5_hrxq*
flow_hw_tir_action_register(struct rte_eth_dev *dev,
			    uint32_t hws_flags,
			    const struct rte_flow_action *action)
{
	struct mlx5_flow_rss_desc rss_desc = {
		.hws_flags = hws_flags,
	};
	struct mlx5_hrxq *hrxq;

	if (action->type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		const struct rte_flow_action_queue *queue = action->conf;

		rss_desc.const_q = &queue->index;
		rss_desc.queue_num = 1;
	} else {
		const struct rte_flow_action_rss *rss = action->conf;

		rss_desc.queue_num = rss->queue_num;
		rss_desc.const_q = rss->queue;
		memcpy(rss_desc.key,
		       !rss->key ? rss_hash_default_key : rss->key,
		       MLX5_RSS_HASH_KEY_LEN);
		rss_desc.key_len = MLX5_RSS_HASH_KEY_LEN;
		rss_desc.types = !rss->types ? RTE_ETH_RSS_IP : rss->types;
		flow_hw_hashfields_set(&rss_desc, &rss_desc.hash_fields);
		flow_dv_action_rss_l34_hash_adjust(rss->types,
						   &rss_desc.hash_fields);
		if (rss->level > 1) {
			rss_desc.hash_fields |= IBV_RX_HASH_INNER;
			rss_desc.tunnel = 1;
		}
	}
	hrxq = mlx5_hrxq_get(dev, &rss_desc);
	return hrxq;
}

/**
 * Destroy DR actions created by action template.
 *
 * For DR actions created during table creation's action translate.
 * Need to destroy the DR action when destroying the table.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 */
static void
__flow_hw_action_template_destroy(struct rte_eth_dev *dev,
				 struct mlx5_hw_actions *acts)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (acts->jump) {
		struct mlx5_flow_group *grp;

		grp = container_of
			(acts->jump, struct mlx5_flow_group, jump);
		mlx5_hlist_unregister(priv->sh->flow_tbls, &grp->entry);
		acts->jump = NULL;
	}
	if (acts->mhdr) {
		if (acts->mhdr->action)
			mlx5dr_action_destroy(acts->mhdr->action);
		mlx5_free(acts->mhdr);
	}
}

/**
 * Append dynamic action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline struct mlx5_action_construct_data *
__flow_hw_act_data_alloc(struct mlx5_priv *priv,
			 enum rte_flow_action_type type,
			 uint16_t action_src,
			 uint16_t action_dst)
{
	struct mlx5_action_construct_data *act_data;
	uint32_t idx = 0;

	act_data = mlx5_ipool_zmalloc(priv->acts_ipool, &idx);
	if (!act_data)
		return NULL;
	act_data->idx = idx;
	act_data->type = type;
	act_data->action_src = action_src;
	act_data->action_dst = action_dst;
	return act_data;
}

/**
 * Append dynamic action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
__flow_hw_act_data_general_append(struct mlx5_priv *priv,
				  struct mlx5_hw_actions *acts,
				  enum rte_flow_action_type type,
				  uint16_t action_src,
				  uint16_t action_dst)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

/**
 * Append dynamic encap action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 * @param[in] len
 *   Length of the data to be updated.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
__flow_hw_act_data_encap_append(struct mlx5_priv *priv,
				struct mlx5_hw_actions *acts,
				enum rte_flow_action_type type,
				uint16_t action_src,
				uint16_t action_dst,
				uint16_t len)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->encap.len = len;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

static __rte_always_inline int
__flow_hw_act_data_hdr_modify_append(struct mlx5_priv *priv,
				     struct mlx5_hw_actions *acts,
				     enum rte_flow_action_type type,
				     uint16_t action_src,
				     uint16_t action_dst,
				     uint16_t mhdr_cmds_off,
				     uint16_t mhdr_cmds_end,
				     bool shared,
				     struct field_modify_info *field,
				     struct field_modify_info *dcopy,
				     uint32_t *mask)
{
	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->modify_header.mhdr_cmds_off = mhdr_cmds_off;
	act_data->modify_header.mhdr_cmds_end = mhdr_cmds_end;
	act_data->modify_header.shared = shared;
	rte_memcpy(act_data->modify_header.field, field,
		   sizeof(*field) * MLX5_ACT_MAX_MOD_FIELDS);
	rte_memcpy(act_data->modify_header.dcopy, dcopy,
		   sizeof(*dcopy) * MLX5_ACT_MAX_MOD_FIELDS);
	rte_memcpy(act_data->modify_header.mask, mask,
		   sizeof(*mask) * MLX5_ACT_MAX_MOD_FIELDS);
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

/**
 * Append shared RSS action to the dynamic action list.
 *
 * @param[in] priv
 *   Pointer to the port private data structure.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] type
 *   Action type.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 * @param[in] idx
 *   Shared RSS index.
 * @param[in] rss
 *   Pointer to the shared RSS info.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
__flow_hw_act_data_shared_rss_append(struct mlx5_priv *priv,
				     struct mlx5_hw_actions *acts,
				     enum rte_flow_action_type type,
				     uint16_t action_src,
				     uint16_t action_dst,
				     uint32_t idx,
				     struct mlx5_shared_action_rss *rss)
{	struct mlx5_action_construct_data *act_data;

	act_data = __flow_hw_act_data_alloc(priv, type, action_src, action_dst);
	if (!act_data)
		return -1;
	act_data->shared_rss.level = rss->origin.level;
	act_data->shared_rss.types = !rss->origin.types ? RTE_ETH_RSS_IP :
				     rss->origin.types;
	act_data->shared_rss.idx = idx;
	LIST_INSERT_HEAD(&acts->act_list, act_data, next);
	return 0;
}

/**
 * Translate shared indirect action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev data structure.
 * @param[in] action
 *   Pointer to the shared indirect rte_flow action.
 * @param[in] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] action_src
 *   Offset of source rte flow action.
 * @param[in] action_dst
 *   Offset of destination DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_shared_action_translate(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				struct mlx5_hw_actions *acts,
				uint16_t action_src,
				uint16_t action_dst)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_shared_action_rss *shared_rss;
	uint32_t act_idx = (uint32_t)(uintptr_t)action->conf;
	uint32_t type = act_idx >> MLX5_INDIRECT_ACTION_TYPE_OFFSET;
	uint32_t idx = act_idx &
		       ((1u << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);

	switch (type) {
	case MLX5_INDIRECT_ACTION_TYPE_RSS:
		shared_rss = mlx5_ipool_get
		  (priv->sh->ipool[MLX5_IPOOL_RSS_SHARED_ACTIONS], idx);
		if (!shared_rss || __flow_hw_act_data_shared_rss_append
		    (priv, acts,
		    (enum rte_flow_action_type)MLX5_RTE_FLOW_ACTION_TYPE_RSS,
		    action_src, action_dst, idx, shared_rss))
			return -1;
		break;
	default:
		DRV_LOG(WARNING, "Unsupported shared action type:%d", type);
		break;
	}
	return 0;
}

static __rte_always_inline bool
flow_hw_action_modify_field_is_shared(const struct rte_flow_action *action,
				      const struct rte_flow_action *mask)
{
	const struct rte_flow_action_modify_field *v = action->conf;
	const struct rte_flow_action_modify_field *m = mask->conf;

	if (v->src.field == RTE_FLOW_FIELD_VALUE) {
		uint32_t j;

		if (m == NULL)
			return false;
		for (j = 0; j < RTE_DIM(m->src.value); ++j) {
			/*
			 * Immediate value is considered to be masked
			 * (and thus shared by all flow rules), if mask
			 * is non-zero. Partial mask over immediate value
			 * is not allowed.
			 */
			if (m->src.value[j])
				return true;
		}
		return false;
	}
	if (v->src.field == RTE_FLOW_FIELD_POINTER)
		return m->src.pvalue != NULL;
	/*
	 * Source field types other than VALUE and
	 * POINTER are always shared.
	 */
	return true;
}

static __rte_always_inline bool
flow_hw_should_insert_nop(const struct mlx5_hw_modify_header_action *mhdr,
			  const struct mlx5_modification_cmd *cmd)
{
	struct mlx5_modification_cmd last_cmd = { { 0 } };
	struct mlx5_modification_cmd new_cmd = { { 0 } };
	const uint32_t cmds_num = mhdr->mhdr_cmds_num;
	unsigned int last_type;
	bool should_insert = false;

	if (cmds_num == 0)
		return false;
	last_cmd = *(&mhdr->mhdr_cmds[cmds_num - 1]);
	last_cmd.data0 = rte_be_to_cpu_32(last_cmd.data0);
	last_cmd.data1 = rte_be_to_cpu_32(last_cmd.data1);
	last_type = last_cmd.action_type;
	new_cmd = *cmd;
	new_cmd.data0 = rte_be_to_cpu_32(new_cmd.data0);
	new_cmd.data1 = rte_be_to_cpu_32(new_cmd.data1);
	switch (new_cmd.action_type) {
	case MLX5_MODIFICATION_TYPE_SET:
	case MLX5_MODIFICATION_TYPE_ADD:
		if (last_type == MLX5_MODIFICATION_TYPE_SET ||
		    last_type == MLX5_MODIFICATION_TYPE_ADD)
			should_insert = new_cmd.field == last_cmd.field;
		else if (last_type == MLX5_MODIFICATION_TYPE_COPY)
			should_insert = new_cmd.field == last_cmd.dst_field;
		else if (last_type == MLX5_MODIFICATION_TYPE_NOP)
			should_insert = false;
		else
			MLX5_ASSERT(false); /* Other types are not supported. */
		break;
	case MLX5_MODIFICATION_TYPE_COPY:
		if (last_type == MLX5_MODIFICATION_TYPE_SET ||
		    last_type == MLX5_MODIFICATION_TYPE_ADD)
			should_insert = (new_cmd.field == last_cmd.field ||
					 new_cmd.dst_field == last_cmd.field);
		else if (last_type == MLX5_MODIFICATION_TYPE_COPY)
			should_insert = (new_cmd.field == last_cmd.dst_field ||
					 new_cmd.dst_field == last_cmd.dst_field);
		else if (last_type == MLX5_MODIFICATION_TYPE_NOP)
			should_insert = false;
		else
			MLX5_ASSERT(false); /* Other types are not supported. */
		break;
	default:
		/* Other action types should be rejected on AT validation. */
		MLX5_ASSERT(false);
		break;
	}
	return should_insert;
}

static __rte_always_inline int
flow_hw_mhdr_cmd_nop_append(struct mlx5_hw_modify_header_action *mhdr)
{
	struct mlx5_modification_cmd *nop;
	uint32_t num = mhdr->mhdr_cmds_num;

	if (num + 1 >= MLX5_MHDR_MAX_CMD)
		return -ENOMEM;
	nop = mhdr->mhdr_cmds + num;
	nop->data0 = 0;
	nop->action_type = MLX5_MODIFICATION_TYPE_NOP;
	nop->data0 = rte_cpu_to_be_32(nop->data0);
	nop->data1 = 0;
	mhdr->mhdr_cmds_num = num + 1;
	return 0;
}

static __rte_always_inline int
flow_hw_mhdr_cmd_append(struct mlx5_hw_modify_header_action *mhdr,
			struct mlx5_modification_cmd *cmd)
{
	uint32_t num = mhdr->mhdr_cmds_num;

	if (num + 1 >= MLX5_MHDR_MAX_CMD)
		return -ENOMEM;
	mhdr->mhdr_cmds[num] = *cmd;
	mhdr->mhdr_cmds_num = num + 1;
	return 0;
}

static __rte_always_inline int
flow_hw_converted_mhdr_cmds_append(struct mlx5_hw_modify_header_action *mhdr,
				   struct mlx5_flow_dv_modify_hdr_resource *resource)
{
	uint32_t idx;
	int ret;

	for (idx = 0; idx < resource->actions_num; ++idx) {
		struct mlx5_modification_cmd *src = &resource->actions[idx];

		if (flow_hw_should_insert_nop(mhdr, src)) {
			ret = flow_hw_mhdr_cmd_nop_append(mhdr);
			if (ret)
				return ret;
		}
		ret = flow_hw_mhdr_cmd_append(mhdr, src);
		if (ret)
			return ret;
	}
	return 0;
}

static __rte_always_inline void
flow_hw_modify_field_init(struct mlx5_hw_modify_header_action *mhdr,
			  struct rte_flow_actions_template *at)
{
	memset(mhdr, 0, sizeof(*mhdr));
	/* Modify header action without any commands is shared by default. */
	mhdr->shared = true;
	mhdr->pos = at->mhdr_off;
}

static __rte_always_inline int
flow_hw_modify_field_compile(struct rte_eth_dev *dev,
			     const struct rte_flow_attr *attr,
			     const struct rte_flow_action *action_start, /* Start of AT actions. */
			     const struct rte_flow_action *action, /* Current action from AT. */
			     const struct rte_flow_action *action_mask, /* Current mask from AT. */
			     struct mlx5_hw_actions *acts,
			     struct mlx5_hw_modify_header_action *mhdr,
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_action_modify_field *conf = action->conf;
	union {
		struct mlx5_flow_dv_modify_hdr_resource resource;
		uint8_t data[sizeof(struct mlx5_flow_dv_modify_hdr_resource) +
			     sizeof(struct mlx5_modification_cmd) * MLX5_MHDR_MAX_CMD];
	} dummy;
	struct mlx5_flow_dv_modify_hdr_resource *resource;
	struct rte_flow_item item = {
		.spec = NULL,
		.mask = NULL
	};
	struct field_modify_info field[MLX5_ACT_MAX_MOD_FIELDS] = {
						{0, 0, MLX5_MODI_OUT_NONE} };
	struct field_modify_info dcopy[MLX5_ACT_MAX_MOD_FIELDS] = {
						{0, 0, MLX5_MODI_OUT_NONE} };
	uint32_t mask[MLX5_ACT_MAX_MOD_FIELDS] = { 0 };
	uint32_t type, value = 0;
	uint16_t cmds_start, cmds_end;
	bool shared;
	int ret;

	/*
	 * Modify header action is shared if previous modify_field actions
	 * are shared and currently compiled action is shared.
	 */
	shared = flow_hw_action_modify_field_is_shared(action, action_mask);
	mhdr->shared &= shared;
	if (conf->src.field == RTE_FLOW_FIELD_POINTER ||
	    conf->src.field == RTE_FLOW_FIELD_VALUE) {
		type = conf->operation == RTE_FLOW_MODIFY_SET ? MLX5_MODIFICATION_TYPE_SET :
								MLX5_MODIFICATION_TYPE_ADD;
		/* For SET/ADD fill the destination field (field) first. */
		mlx5_flow_field_id_to_modify_info(&conf->dst, field, mask,
						  conf->width, dev,
						  attr, error);
		item.spec = conf->src.field == RTE_FLOW_FIELD_POINTER ?
				(void *)(uintptr_t)conf->src.pvalue :
				(void *)(uintptr_t)&conf->src.value;
		if (conf->dst.field == RTE_FLOW_FIELD_META ||
		    conf->dst.field == RTE_FLOW_FIELD_TAG) {
			value = *(const unaligned_uint32_t *)item.spec;
			value = rte_cpu_to_be_32(value);
			item.spec = &value;
		} else if (conf->dst.field == RTE_FLOW_FIELD_GTP_PSC_QFI) {
			/*
			 * QFI is passed as an uint8_t integer, but it is accessed through
			 * a 2nd least significant byte of a 32-bit field in modify header command.
			 */
			value = *(const uint8_t *)item.spec;
			value = rte_cpu_to_be_32(value << 8);
			item.spec = &value;
		}
	} else {
		type = MLX5_MODIFICATION_TYPE_COPY;
		/* For COPY fill the destination field (dcopy) without mask. */
		mlx5_flow_field_id_to_modify_info(&conf->dst, dcopy, NULL,
						  conf->width, dev,
						  attr, error);
		/* Then construct the source field (field) with mask. */
		mlx5_flow_field_id_to_modify_info(&conf->src, field, mask,
						  conf->width, dev,
						  attr, error);
	}
	item.mask = &mask;
	memset(&dummy, 0, sizeof(dummy));
	resource = &dummy.resource;
	ret = flow_dv_convert_modify_action(&item, field, dcopy, resource, type, error);
	if (ret)
		return ret;
	MLX5_ASSERT(resource->actions_num > 0);
	/*
	 * If previous modify field action collide with this one, then insert NOP command.
	 * This NOP command will not be a part of action's command range used to update commands
	 * on rule creation.
	 */
	if (flow_hw_should_insert_nop(mhdr, &resource->actions[0])) {
		ret = flow_hw_mhdr_cmd_nop_append(mhdr);
		if (ret)
			return rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
						  NULL, "too many modify field operations specified");
	}
	cmds_start = mhdr->mhdr_cmds_num;
	ret = flow_hw_converted_mhdr_cmds_append(mhdr, resource);
	if (ret)
		return rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "too many modify field operations specified");

	cmds_end = mhdr->mhdr_cmds_num;
	if (shared)
		return 0;
	ret = __flow_hw_act_data_hdr_modify_append(priv, acts, RTE_FLOW_ACTION_TYPE_MODIFY_FIELD,
						   action - action_start, mhdr->pos,
						   cmds_start, cmds_end, shared,
						   field, dcopy, mask);
	if (ret)
		return rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "not enough memory to store modify field metadata");
	return 0;
}

/**
 * Translate rte_flow actions to DR action.
 *
 * As the action template has already indicated the actions. Translate
 * the rte_flow actions to DR action if possbile. So in flow create
 * stage we will save cycles from handing the actions' organizing.
 * For the actions with limited information, need to add these to a
 * list.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] table_attr
 *   Pointer to the table attributes.
 * @param[in] item_templates
 *   Item template array to be binded to the table.
 * @param[in/out] acts
 *   Pointer to the template HW steering DR actions.
 * @param[in] at
 *   Action template.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static int
flow_hw_actions_translate(struct rte_eth_dev *dev,
			  const struct rte_flow_template_table_attr *table_attr,
			  struct mlx5_hw_actions *acts,
			  struct rte_flow_actions_template *at,
			  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	const struct rte_flow_attr *attr = &table_attr->flow_attr;
	struct rte_flow_action *actions = at->actions;
	struct rte_flow_action *action_start = actions;
	struct rte_flow_action *masks = at->masks;
	enum mlx5dr_action_reformat_type refmt_type = 0;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	const struct rte_flow_item *enc_item = NULL, *enc_item_m = NULL;
	uint16_t reformat_pos = MLX5_HW_MAX_ACTS, reformat_src = 0;
	uint8_t *encap_data = NULL, *encap_data_m = NULL;
	size_t data_size = 0;
	struct mlx5_hw_modify_header_action mhdr = { 0 };
	bool actions_end = false;
	uint32_t type, i;
	int err;

	flow_hw_modify_field_init(&mhdr, at);
	if (attr->transfer)
		type = MLX5DR_TABLE_TYPE_FDB;
	else if (attr->egress)
		type = MLX5DR_TABLE_TYPE_NIC_TX;
	else
		type = MLX5DR_TABLE_TYPE_NIC_RX;
	for (i = 0; !actions_end; actions++, masks++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_INDIRECT:
			if (!attr->group) {
				DRV_LOG(ERR, "Indirect action is not supported in root table.");
				goto err;
			}
			if (actions->conf && masks->conf) {
				if (flow_hw_shared_action_translate
				(dev, actions, acts, actions - action_start, i))
					goto err;
			} else if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)){
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			acts->rule_acts[i++].action =
				priv->hw_drop[!!attr->group][type];
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			acts->mark = true;
			if (masks->conf)
				acts->rule_acts[i].tag.value =
					mlx5_flow_mark_set
					(((const struct rte_flow_action_mark *)
					(masks->conf))->id);
			else if (__flow_hw_act_data_general_append(priv, acts,
				actions->type, actions - action_start, i))
				goto err;
			acts->rule_acts[i++].action =
				priv->hw_tag[!!attr->group];
			flow_hw_rxq_flag_set(dev, true);
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			if (masks->conf) {
				uint32_t jump_group =
					((const struct rte_flow_action_jump *)
					actions->conf)->group;
				acts->jump = flow_hw_jump_action_register
						(dev, attr, jump_group, error);
				if (!acts->jump)
					goto err;
				acts->rule_acts[i].action = (!!attr->group) ?
						acts->jump->hws_action :
						acts->jump->root_action;
			} else if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)){
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			if (masks->conf) {
				acts->tir = flow_hw_tir_action_register
				(dev,
				 mlx5_hw_act_flag[!!attr->group][type],
				 actions);
				if (!acts->tir)
					goto err;
				acts->rule_acts[i].action =
					acts->tir->action;
			} else if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)) {
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			if (masks->conf) {
				acts->tir = flow_hw_tir_action_register
				(dev,
				 mlx5_hw_act_flag[!!attr->group][type],
				 actions);
				if (!acts->tir)
					goto err;
				acts->rule_acts[i].action =
					acts->tir->action;
			} else if (__flow_hw_act_data_general_append
					(priv, acts, actions->type,
					 actions - action_start, i)) {
				goto err;
			}
			i++;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			enc_item = ((const struct rte_flow_action_vxlan_encap *)
				   actions->conf)->definition;
			if (masks->conf)
				enc_item_m = ((const struct rte_flow_action_vxlan_encap *)
					     masks->conf)->definition;
			reformat_pos = i++;
			reformat_src = actions - action_start;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			enc_item = ((const struct rte_flow_action_nvgre_encap *)
				   actions->conf)->definition;
			if (masks->conf)
				enc_item_m = ((const struct rte_flow_action_nvgre_encap *)
					     masks->conf)->definition;
			reformat_pos = i++;
			reformat_src = actions - action_start;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			MLX5_ASSERT(reformat_pos == MLX5_HW_MAX_ACTS);
			reformat_pos = i++;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			raw_encap_data =
				(const struct rte_flow_action_raw_encap *)
				 masks->conf;
			if (raw_encap_data)
				encap_data_m = raw_encap_data->data;
			raw_encap_data =
				(const struct rte_flow_action_raw_encap *)
				 actions->conf;
			encap_data = raw_encap_data->data;
			data_size = raw_encap_data->size;
			if (reformat_pos != MLX5_HW_MAX_ACTS) {
				refmt_type = data_size <
				MLX5_ENCAPSULATION_DECISION_SIZE ?
				MLX5DR_ACTION_REFORMAT_TYPE_TNL_L3_TO_L2 :
				MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L3;
			} else {
				reformat_pos = i++;
				refmt_type =
				MLX5DR_ACTION_REFORMAT_TYPE_L2_TO_TNL_L2;
			}
			reformat_src = actions - action_start;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			reformat_pos = i++;
			refmt_type = MLX5DR_ACTION_REFORMAT_TYPE_TNL_L2_TO_L2;
			break;
		case RTE_FLOW_ACTION_TYPE_SEND_TO_KERNEL:
			DRV_LOG(ERR, "send to kernel action is not supported in HW steering.");
			goto err;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			if (mhdr.pos == UINT16_MAX)
				mhdr.pos = i++;
			err = flow_hw_modify_field_compile(dev, attr, action_start,
							   actions, masks, acts, &mhdr,
							   error);
			if (err)
				goto err;
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			actions_end = true;
			break;
		default:
			break;
		}
	}
	if (mhdr.pos != UINT16_MAX) {
		uint32_t flags;
		uint32_t bulk_size;
		size_t mhdr_len;

		acts->mhdr = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*acts->mhdr),
					 0, SOCKET_ID_ANY);
		if (!acts->mhdr)
			goto err;
		rte_memcpy(acts->mhdr, &mhdr, sizeof(*acts->mhdr));
		mhdr_len = sizeof(struct mlx5_modification_cmd) * acts->mhdr->mhdr_cmds_num;
		flags = mlx5_hw_act_flag[!!attr->group][type];
		if (acts->mhdr->shared) {
			flags |= MLX5DR_ACTION_FLAG_SHARED;
			bulk_size = 0;
		} else {
			bulk_size = rte_log2_u32(table_attr->nb_flows);
		}
		acts->mhdr->action = mlx5dr_action_create_modify_header
				(priv->dr_ctx, mhdr_len, (__be64 *)acts->mhdr->mhdr_cmds,
				 bulk_size, flags);
		if (!acts->mhdr->action)
			goto err;
		acts->rule_acts[acts->mhdr->pos].action = acts->mhdr->action;
	}
	if (reformat_pos != MLX5_HW_MAX_ACTS) {
		uint8_t buf[MLX5_ENCAP_MAX_LEN];
		bool shared_rfmt = true;

		if (enc_item) {
			MLX5_ASSERT(!encap_data);
			if (flow_dv_convert_encap_data(enc_item, buf, &data_size, error))
				goto err;
			encap_data = buf;
			if (!enc_item_m)
				shared_rfmt = false;
		} else if (encap_data && !encap_data_m) {
			shared_rfmt = false;
		}
		acts->encap_decap = mlx5_malloc(MLX5_MEM_ZERO,
				    sizeof(*acts->encap_decap) + data_size,
				    0, SOCKET_ID_ANY);
		if (!acts->encap_decap)
			goto err;
		if (data_size) {
			acts->encap_decap->data_size = data_size;
			memcpy(acts->encap_decap->data, encap_data, data_size);
		}
		acts->encap_decap->action = mlx5dr_action_create_reformat
				(priv->dr_ctx, refmt_type,
				 data_size, encap_data,
				 shared_rfmt ? 0 : rte_log2_u32(table_attr->nb_flows),
				 mlx5_hw_act_flag[!!attr->group][type] |
				 (shared_rfmt ? MLX5DR_ACTION_FLAG_SHARED : 0));
		if (!acts->encap_decap->action)
			goto err;
		acts->rule_acts[reformat_pos].action =
						acts->encap_decap->action;
		acts->rule_acts[reformat_pos].reformat.data =
						acts->encap_decap->data;
		if (shared_rfmt)
			acts->rule_acts[reformat_pos].reformat.offset = 0;
		else if (__flow_hw_act_data_encap_append(priv, acts,
				 (action_start + reformat_src)->type,
				 reformat_src, reformat_pos, data_size))
			goto err;
		acts->encap_decap->shared = shared_rfmt;
		acts->encap_decap_pos = reformat_pos;
	}
	acts->acts_num = i;
	return 0;
err:
	err = rte_errno;
	__flow_hw_action_template_destroy(dev, acts);
	return rte_flow_error_set(error, err,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "fail to create rte table");
}

/**
 * Get shared indirect action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev data structure.
 * @param[in] act_data
 *   Pointer to the recorded action construct data.
 * @param[in] item_flags
 *   The matcher itme_flags used for RSS lookup.
 * @param[in] rule_act
 *   Pointer to the shared action's destination rule DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_shared_action_get(struct rte_eth_dev *dev,
			  struct mlx5_action_construct_data *act_data,
			  const uint64_t item_flags,
			  struct mlx5dr_rule_action *rule_act)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_flow_rss_desc rss_desc = { 0 };
	uint64_t hash_fields = 0;
	uint32_t hrxq_idx = 0;
	struct mlx5_hrxq *hrxq = NULL;
	int act_type = act_data->type;

	switch (act_type) {
	case MLX5_RTE_FLOW_ACTION_TYPE_RSS:
		rss_desc.level = act_data->shared_rss.level;
		rss_desc.types = act_data->shared_rss.types;
		flow_dv_hashfields_set(item_flags, &rss_desc, &hash_fields);
		hrxq_idx = flow_dv_action_rss_hrxq_lookup
			(dev, act_data->shared_rss.idx, hash_fields);
		if (hrxq_idx)
			hrxq = mlx5_ipool_get(priv->sh->ipool[MLX5_IPOOL_HRXQ],
					      hrxq_idx);
		if (hrxq) {
			rule_act->action = hrxq->action;
			return 0;
		}
		break;
	default:
		DRV_LOG(WARNING, "Unsupported shared action type:%d",
			act_data->type);
		break;
	}
	return -1;
}

/**
 * Construct shared indirect action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev data structure.
 * @param[in] action
 *   Pointer to the shared indirect rte_flow action.
 * @param[in] table
 *   Pointer to the flow table.
 * @param[in] it_idx
 *   Item template index the action template refer to.
 * @param[in] rule_act
 *   Pointer to the shared action's destination rule DR action.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_shared_action_construct(struct rte_eth_dev *dev,
				const struct rte_flow_action *action,
				struct rte_flow_template_table *table,
				const uint8_t it_idx,
				struct mlx5dr_rule_action *rule_act)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_action_construct_data act_data;
	struct mlx5_shared_action_rss *shared_rss;
	uint32_t act_idx = (uint32_t)(uintptr_t)action->conf;
	uint32_t type = act_idx >> MLX5_INDIRECT_ACTION_TYPE_OFFSET;
	uint32_t idx = act_idx &
		       ((1u << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1);
	uint64_t item_flags;

	memset(&act_data, 0, sizeof(act_data));
	switch (type) {
	case MLX5_INDIRECT_ACTION_TYPE_RSS:
		act_data.type = MLX5_RTE_FLOW_ACTION_TYPE_RSS;
		shared_rss = mlx5_ipool_get
			(priv->sh->ipool[MLX5_IPOOL_RSS_SHARED_ACTIONS], idx);
		if (!shared_rss)
			return -1;
		act_data.shared_rss.idx = idx;
		act_data.shared_rss.level = shared_rss->origin.level;
		act_data.shared_rss.types = !shared_rss->origin.types ?
					    RTE_ETH_RSS_IP :
					    shared_rss->origin.types;
		item_flags = table->its[it_idx]->item_flags;
		if (flow_hw_shared_action_get
				(dev, &act_data, item_flags, rule_act))
			return -1;
		break;
	default:
		DRV_LOG(WARNING, "Unsupported shared action type:%d", type);
		break;
	}
	return 0;
}

static __rte_always_inline int
flow_hw_mhdr_cmd_is_nop(const struct mlx5_modification_cmd *cmd)
{
	struct mlx5_modification_cmd cmd_he = {
		.data0 = rte_be_to_cpu_32(cmd->data0),
		.data1 = 0,
	};

	return cmd_he.action_type == MLX5_MODIFICATION_TYPE_NOP;
}

/**
 * Construct flow action array.
 *
 * For action template contains dynamic actions, these actions need to
 * be updated according to the rte_flow action during flow creation.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] job
 *   Pointer to job descriptor.
 * @param[in] hw_acts
 *   Pointer to translated actions from template.
 * @param[in] it_idx
 *   Item template index the action template refer to.
 * @param[in] actions
 *   Array of rte_flow action need to be checked.
 * @param[in] rule_acts
 *   Array of DR rule actions to be used during flow creation..
 * @param[in] acts_num
 *   Pointer to the real acts_num flow has.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_modify_field_construct(struct mlx5_hw_q_job *job,
			       struct mlx5_action_construct_data *act_data,
			       const struct mlx5_hw_actions *hw_acts,
			       const struct rte_flow_action *action)
{
	const struct rte_flow_action_modify_field *mhdr_action = action->conf;
	uint8_t values[16] = { 0 };
	unaligned_uint32_t *value_p;
	uint32_t i;
	struct field_modify_info *field;

	if (!hw_acts->mhdr)
		return -1;
	if (hw_acts->mhdr->shared || act_data->modify_header.shared)
		return 0;
	MLX5_ASSERT(mhdr_action->operation == RTE_FLOW_MODIFY_SET ||
		    mhdr_action->operation == RTE_FLOW_MODIFY_ADD);
	if (mhdr_action->src.field != RTE_FLOW_FIELD_VALUE &&
	    mhdr_action->src.field != RTE_FLOW_FIELD_POINTER)
		return 0;
	if (mhdr_action->src.field == RTE_FLOW_FIELD_VALUE)
		rte_memcpy(values, &mhdr_action->src.value, sizeof(values));
	else
		rte_memcpy(values, mhdr_action->src.pvalue, sizeof(values));
	if (mhdr_action->dst.field == RTE_FLOW_FIELD_META ||
	    mhdr_action->dst.field == RTE_FLOW_FIELD_TAG) {
		value_p = (unaligned_uint32_t *)values;
		*value_p = rte_cpu_to_be_32(*value_p);
	} else if (mhdr_action->dst.field == RTE_FLOW_FIELD_GTP_PSC_QFI) {
		uint32_t tmp;

		/*
		 * QFI is passed as an uint8_t integer, but it is accessed through
		 * a 2nd least significant byte of a 32-bit field in modify header command.
		 */
		tmp = values[0];
		value_p = (unaligned_uint32_t *)values;
		*value_p = rte_cpu_to_be_32(tmp << 8);
	}
	i = act_data->modify_header.mhdr_cmds_off;
	field = act_data->modify_header.field;
	do {
		uint32_t off_b;
		uint32_t mask;
		uint32_t data;
		const uint8_t *mask_src;

		if (i >= act_data->modify_header.mhdr_cmds_end)
			return -1;
		if (flow_hw_mhdr_cmd_is_nop(&job->mhdr_cmd[i])) {
			++i;
			continue;
		}
		mask_src = (const uint8_t *)act_data->modify_header.mask;
		mask = flow_dv_fetch_field(mask_src + field->offset, field->size);
		if (!mask) {
			++field;
			continue;
		}
		off_b = rte_bsf32(mask);
		data = flow_dv_fetch_field(values + field->offset, field->size);
		data = (data & mask) >> off_b;
		job->mhdr_cmd[i++].data1 = rte_cpu_to_be_32(data);
		++field;
	} while (field->size);
	return 0;
}

/**
 * Construct flow action array.
 *
 * For action template contains dynamic actions, these actions need to
 * be updated according to the rte_flow action during flow creation.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] job
 *   Pointer to job descriptor.
 * @param[in] hw_acts
 *   Pointer to translated actions from template.
 * @param[in] it_idx
 *   Item template index the action template refer to.
 * @param[in] actions
 *   Array of rte_flow action need to be checked.
 * @param[in] rule_acts
 *   Array of DR rule actions to be used during flow creation..
 * @param[in] acts_num
 *   Pointer to the real acts_num flow has.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static __rte_always_inline int
flow_hw_actions_construct(struct rte_eth_dev *dev,
			  struct mlx5_hw_q_job *job,
			  const struct mlx5_hw_actions *hw_acts,
			  const uint8_t it_idx,
			  const struct rte_flow_action actions[],
			  struct mlx5dr_rule_action *rule_acts,
			  uint32_t *acts_num)
{
	struct rte_flow_template_table *table = job->flow->table;
	struct mlx5_action_construct_data *act_data;
	const struct rte_flow_action *action;
	const struct rte_flow_action_raw_encap *raw_encap_data;
	const struct rte_flow_item *enc_item = NULL;
	uint8_t *buf = job->encap_data;
	struct rte_flow_attr attr = {
			.ingress = 1,
	};
	uint32_t ft_flag;
	size_t encap_len = 0;
	int ret;

	memcpy(rule_acts, hw_acts->rule_acts,
	       sizeof(*rule_acts) * hw_acts->acts_num);
	*acts_num = hw_acts->acts_num;
	if (LIST_EMPTY(&hw_acts->act_list))
		return 0;
	attr.group = table->grp->group_id;
	ft_flag = mlx5_hw_act_flag[!!table->grp->group_id][table->type];
	if (table->type == MLX5DR_TABLE_TYPE_FDB) {
		attr.transfer = 1;
		attr.ingress = 1;
	} else if (table->type == MLX5DR_TABLE_TYPE_NIC_TX) {
		attr.egress = 1;
		attr.ingress = 0;
	} else {
		attr.ingress = 1;
	}
	if (hw_acts->mhdr && hw_acts->mhdr->mhdr_cmds_num > 0) {
		uint16_t pos = hw_acts->mhdr->pos;

		if (!hw_acts->mhdr->shared) {
			rule_acts[pos].modify_header.offset =
						job->flow->idx - 1;
			rule_acts[pos].modify_header.data =
						(uint8_t *)job->mhdr_cmd;
			rte_memcpy(job->mhdr_cmd, hw_acts->mhdr->mhdr_cmds,
				   sizeof(*job->mhdr_cmd) * hw_acts->mhdr->mhdr_cmds_num);
		}
	}
	LIST_FOREACH(act_data, &hw_acts->act_list, next) {
		uint32_t jump_group;
		uint32_t tag;
		uint64_t item_flags;
		struct mlx5_hw_jump_action *jump;
		struct mlx5_hrxq *hrxq;

		action = &actions[act_data->action_src];
		MLX5_ASSERT(action->type == RTE_FLOW_ACTION_TYPE_INDIRECT ||
			    (int)action->type == act_data->type);
		switch (act_data->type) {
		case RTE_FLOW_ACTION_TYPE_INDIRECT:
			if (flow_hw_shared_action_construct
					(dev, action, table, it_idx,
					 &rule_acts[act_data->action_dst]))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			tag = mlx5_flow_mark_set
			      (((const struct rte_flow_action_mark *)
			      (action->conf))->id);
			rule_acts[act_data->action_dst].tag.value = tag;
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			jump_group = ((const struct rte_flow_action_jump *)
						action->conf)->group;
			jump = flow_hw_jump_action_register
				(dev, &attr, jump_group, NULL);
			if (!jump)
				return -1;
			rule_acts[act_data->action_dst].action =
			(!!attr.group) ? jump->hws_action : jump->root_action;
			job->flow->jump = jump;
			job->flow->fate_type = MLX5_FLOW_FATE_JUMP;
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			hrxq = flow_hw_tir_action_register(dev,
					ft_flag,
					action);
			if (!hrxq)
				return -1;
			rule_acts[act_data->action_dst].action = hrxq->action;
			job->flow->hrxq = hrxq;
			job->flow->fate_type = MLX5_FLOW_FATE_QUEUE;
			break;
		case MLX5_RTE_FLOW_ACTION_TYPE_RSS:
			item_flags = table->its[it_idx]->item_flags;
			if (flow_hw_shared_action_get
				(dev, act_data, item_flags,
				 &rule_acts[act_data->action_dst]))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			enc_item = ((const struct rte_flow_action_vxlan_encap *)
				   action->conf)->definition;
			if (flow_dv_convert_encap_data(enc_item, buf, &encap_len, NULL))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			enc_item = ((const struct rte_flow_action_nvgre_encap *)
				   action->conf)->definition;
			if (flow_dv_convert_encap_data(enc_item, buf, &encap_len, NULL))
				return -1;
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			raw_encap_data =
				(const struct rte_flow_action_raw_encap *)
				 action->conf;
			rte_memcpy((void *)buf, raw_encap_data->data, act_data->encap.len);
			MLX5_ASSERT(raw_encap_data->size ==
				    act_data->encap.len);
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			ret = flow_hw_modify_field_construct(job,
							     act_data,
							     hw_acts,
							     action);
			if (ret)
				return -1;
			break;
		default:
			break;
		}
	}
	if (hw_acts->encap_decap && !hw_acts->encap_decap->shared) {
		rule_acts[hw_acts->encap_decap_pos].reformat.offset =
				job->flow->idx - 1;
		rule_acts[hw_acts->encap_decap_pos].reformat.data = buf;
	}
	return 0;
}

/**
 * Enqueue HW steering flow creation.
 *
 * The flow will be applied to the HW only if the postpone bit is not set or
 * the extra push function is called.
 * The flow creation status should be checked from dequeue result.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to create the flow.
 * @param[in] attr
 *   Pointer to the flow operation attributes.
 * @param[in] items
 *   Items with flow spec value.
 * @param[in] pattern_template_index
 *   The item pattern flow follows from the table.
 * @param[in] actions
 *   Action with flow spec value.
 * @param[in] action_template_index
 *   The action pattern flow follows from the table.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Flow pointer on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow *
flow_hw_async_flow_create(struct rte_eth_dev *dev,
			  uint32_t queue,
			  const struct rte_flow_op_attr *attr,
			  struct rte_flow_template_table *table,
			  const struct rte_flow_item items[],
			  uint8_t pattern_template_index,
			  const struct rte_flow_action actions[],
			  uint8_t action_template_index,
			  void *user_data,
			  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_rule_attr rule_attr = {
		.queue_id = queue,
		.user_data = user_data,
		.burst = attr->postpone,
	};
	struct mlx5dr_rule_action rule_acts[MLX5_HW_MAX_ACTS];
	struct mlx5_hw_actions *hw_acts;
	struct rte_flow_hw *flow;
	struct mlx5_hw_q_job *job;
	uint32_t acts_num, flow_idx;
	int ret;

	if (unlikely(!priv->hw_q[queue].job_idx)) {
		rte_errno = ENOMEM;
		goto error;
	}
	flow = mlx5_ipool_zmalloc(table->flow, &flow_idx);
	if (!flow)
		goto error;
	/*
	 * Set the table here in order to know the destination table
	 * when free the flow afterwards.
	 */
	flow->table = table;
	flow->idx = flow_idx;
	job = priv->hw_q[queue].job[--priv->hw_q[queue].job_idx];
	/*
	 * Set the job type here in order to know if the flow memory
	 * should be freed or not when get the result from dequeue.
	 */
	job->type = MLX5_HW_Q_JOB_TYPE_CREATE;
	job->flow = flow;
	job->user_data = user_data;
	rule_attr.user_data = job;
	hw_acts = &table->ats[action_template_index].acts;
	/* Construct the flow action array based on the input actions.*/
	flow_hw_actions_construct(dev, job, hw_acts, pattern_template_index,
				  actions, rule_acts, &acts_num);
	ret = mlx5dr_rule_create(table->matcher,
				 pattern_template_index, items,
				 action_template_index, rule_acts,
				 &rule_attr, (struct mlx5dr_rule *)flow->rule);
	if (likely(!ret))
		return (struct rte_flow *)flow;
	/* Flow created fail, return the descriptor and flow memory. */
	mlx5_ipool_free(table->flow, flow_idx);
	priv->hw_q[queue].job_idx++;
error:
	rte_flow_error_set(error, rte_errno,
			   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			   "fail to create rte flow");
	return NULL;
}

/**
 * Enqueue HW steering flow destruction.
 *
 * The flow will be applied to the HW only if the postpone bit is not set or
 * the extra push function is called.
 * The flow destruction status should be checked from dequeue result.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to destroy the flow.
 * @param[in] attr
 *   Pointer to the flow operation attributes.
 * @param[in] flow
 *   Pointer to the flow to be destroyed.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_async_flow_destroy(struct rte_eth_dev *dev,
			   uint32_t queue,
			   const struct rte_flow_op_attr *attr,
			   struct rte_flow *flow,
			   void *user_data,
			   struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_rule_attr rule_attr = {
		.queue_id = queue,
		.user_data = user_data,
		.burst = attr->postpone,
	};
	struct rte_flow_hw *fh = (struct rte_flow_hw *)flow;
	struct mlx5_hw_q_job *job;
	int ret;

	if (unlikely(!priv->hw_q[queue].job_idx)) {
		rte_errno = ENOMEM;
		goto error;
	}
	job = priv->hw_q[queue].job[--priv->hw_q[queue].job_idx];
	job->type = MLX5_HW_Q_JOB_TYPE_DESTROY;
	job->user_data = user_data;
	job->flow = fh;
	rule_attr.user_data = job;
	ret = mlx5dr_rule_destroy((struct mlx5dr_rule *)fh->rule, &rule_attr);
	if (likely(!ret))
		return 0;
	priv->hw_q[queue].job_idx++;
error:
	return rte_flow_error_set(error, rte_errno,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"fail to create rte flow");
}

/**
 * Pull the enqueued flows.
 *
 * For flows enqueued from creation/destruction, the status should be
 * checked from the dequeue result.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to pull the result.
 * @param[in/out] res
 *   Array to save the results.
 * @param[in] n_res
 *   Available result with the array.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Result number on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_pull(struct rte_eth_dev *dev,
	     uint32_t queue,
	     struct rte_flow_op_result res[],
	     uint16_t n_res,
	     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_q_job *job;
	int ret, i;

	ret = mlx5dr_send_queue_poll(priv->dr_ctx, queue, res, n_res);
	if (ret < 0)
		return rte_flow_error_set(error, rte_errno,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"fail to query flow queue");
	for (i = 0; i <  ret; i++) {
		job = (struct mlx5_hw_q_job *)res[i].user_data;
		/* Restore user data. */
		res[i].user_data = job->user_data;
		if (job->type == MLX5_HW_Q_JOB_TYPE_DESTROY) {
			if (job->flow->fate_type == MLX5_FLOW_FATE_JUMP)
				flow_hw_jump_release(dev, job->flow->jump);
			else if (job->flow->fate_type == MLX5_FLOW_FATE_QUEUE)
				mlx5_hrxq_obj_release(dev, job->flow->hrxq);
			mlx5_ipool_free(job->flow->table->flow, job->flow->idx);
		}
		priv->hw_q[queue].job[priv->hw_q[queue].job_idx++] = job;
	}
	return ret;
}

/**
 * Push the enqueued flows to HW.
 *
 * Force apply all the enqueued flows to the HW.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to push the flow.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_push(struct rte_eth_dev *dev,
	     uint32_t queue,
	     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int ret;

	ret = mlx5dr_send_queue_action(priv->dr_ctx, queue,
				       MLX5DR_SEND_QUEUE_ACTION_DRAIN);
	if (ret) {
		rte_flow_error_set(error, rte_errno,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "fail to push flows");
		return ret;
	}
	return 0;
}

/**
 * Drain the enqueued flows' completion.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   The queue to pull the flow.
 * @param[in] pending_rules
 *   The pending flow number.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
static int
__flow_hw_pull_comp(struct rte_eth_dev *dev,
		    uint32_t queue,
		    uint32_t pending_rules,
		    struct rte_flow_error *error)
{
	struct rte_flow_op_result comp[BURST_THR];
	int ret, i, empty_loop = 0;

	flow_hw_push(dev, queue, error);
	while (pending_rules) {
		ret = flow_hw_pull(dev, queue, comp, BURST_THR, error);
		if (ret < 0)
			return -1;
		if (!ret) {
			rte_delay_us_sleep(20000);
			if (++empty_loop > 5) {
				DRV_LOG(WARNING, "No available dequeue, quit.");
				break;
			}
			continue;
		}
		for (i = 0; i < ret; i++) {
			if (comp[i].status == RTE_FLOW_OP_ERROR)
				DRV_LOG(WARNING, "Flow flush get error CQE.");
		}
		if ((uint32_t)ret > pending_rules) {
			DRV_LOG(WARNING, "Flow flush get extra CQE.");
			return rte_flow_error_set(error, ERANGE,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
					"get extra CQE");
		}
		pending_rules -= ret;
		empty_loop = 0;
	}
	return 0;
}

/**
 * Flush created flows.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    0 on success, negative value otherwise and rte_errno is set.
 */
int
flow_hw_q_flow_flush(struct rte_eth_dev *dev,
		     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_hw_q *hw_q;
	struct rte_flow_template_table *tbl;
	struct rte_flow_hw *flow;
	struct rte_flow_op_attr attr = {
		.postpone = 0,
	};
	uint32_t pending_rules = 0;
	uint32_t queue;
	uint32_t fidx;

	/*
	 * Ensure to push and dequeue all the enqueued flow
	 * creation/destruction jobs in case user forgot to
	 * dequeue. Or the enqueued created flows will be
	 * leaked. The forgotten dequeues would also cause
	 * flow flush get extra CQEs as expected and pending_rules
	 * be minus value.
	 */
	for (queue = 0; queue < priv->nb_queue; queue++) {
		hw_q = &priv->hw_q[queue];
		if (__flow_hw_pull_comp(dev, queue, hw_q->size - hw_q->job_idx,
					error))
			return -1;
	}
	/* Flush flow per-table from MLX5_DEFAULT_FLUSH_QUEUE. */
	hw_q = &priv->hw_q[MLX5_DEFAULT_FLUSH_QUEUE];
	LIST_FOREACH(tbl, &priv->flow_hw_tbl, next) {
		MLX5_IPOOL_FOREACH(tbl->flow, fidx, flow) {
			if (flow_hw_async_flow_destroy(dev,
						MLX5_DEFAULT_FLUSH_QUEUE,
						&attr,
						(struct rte_flow *)flow,
						NULL,
						error))
				return -1;
			pending_rules++;
			/* Drain completion with queue size. */
			if (pending_rules >= hw_q->size) {
				if (__flow_hw_pull_comp(dev,
						MLX5_DEFAULT_FLUSH_QUEUE,
						pending_rules, error))
					return -1;
				pending_rules = 0;
			}
		}
	}
	/* Drain left completion. */
	if (pending_rules &&
	    __flow_hw_pull_comp(dev, MLX5_DEFAULT_FLUSH_QUEUE, pending_rules,
				error))
		return -1;
	return 0;
}

/**
 * Create flow table.
 *
 * The input item and action templates will be binded to the table.
 * Flow memory will also be allocated. Matcher will be created based
 * on the item template. Action will be translated to the dedicated
 * DR action if possible.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] attr
 *   Pointer to the table attributes.
 * @param[in] item_templates
 *   Item template array to be binded to the table.
 * @param[in] nb_item_templates
 *   Number of item template.
 * @param[in] action_templates
 *   Action template array to be binded to the table.
 * @param[in] nb_action_templates
 *   Number of action template.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *    Table on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_template_table *
flow_hw_table_create(struct rte_eth_dev *dev,
		     const struct rte_flow_template_table_attr *attr,
		     struct rte_flow_pattern_template *item_templates[],
		     uint8_t nb_item_templates,
		     struct rte_flow_actions_template *action_templates[],
		     uint8_t nb_action_templates,
		     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_matcher_attr matcher_attr = {0};
	struct rte_flow_template_table *tbl = NULL;
	struct mlx5_flow_group *grp;
	struct mlx5dr_match_template *mt[MLX5_HW_TBL_MAX_ITEM_TEMPLATE];
	struct rte_flow_attr flow_attr = attr->flow_attr;
	struct mlx5_flow_cb_ctx ctx = {
		.dev = dev,
		.error = error,
		.data = &flow_attr,
	};
	struct mlx5_indexed_pool_config cfg = {
		.size = sizeof(struct rte_flow_hw) + mlx5dr_rule_get_handle_size(),
		.trunk_size = 1 << 12,
		.per_core_cache = 1 << 13,
		.need_lock = 1,
		.release_mem_en = !!priv->sh->config.reclaim_mode,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "mlx5_hw_table_flow",
	};
	struct mlx5_list_entry *ge;
	uint32_t i, max_tpl = MLX5_HW_TBL_MAX_ITEM_TEMPLATE;
	uint32_t nb_flows = rte_align32pow2(attr->nb_flows);
	int err;

	/* HWS layer accepts only 1 item template with root table. */
	if (!attr->flow_attr.group)
		max_tpl = 1;
	cfg.max_idx = nb_flows;
	/* For table has very limited flows, disable cache. */
	if (nb_flows < cfg.trunk_size) {
		cfg.per_core_cache = 0;
		cfg.trunk_size = nb_flows;
	}
	/* Check if we requires too many templates. */
	if (nb_item_templates > max_tpl ||
	    nb_action_templates > MLX5_HW_TBL_MAX_ACTION_TEMPLATE) {
		rte_errno = EINVAL;
		goto error;
	}
	/* Allocate the table memory. */
	tbl = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*tbl), 0, rte_socket_id());
	if (!tbl)
		goto error;
	/* Allocate flow indexed pool. */
	tbl->flow = mlx5_ipool_create(&cfg);
	if (!tbl->flow)
		goto error;
	/* Register the flow group. */
	ge = mlx5_hlist_register(priv->sh->groups, attr->flow_attr.group, &ctx);
	if (!ge)
		goto error;
	grp = container_of(ge, struct mlx5_flow_group, entry);
	tbl->grp = grp;
	/* Prepare matcher information. */
	matcher_attr.priority = attr->flow_attr.priority;
	matcher_attr.mode = MLX5DR_MATCHER_RESOURCE_MODE_RULE;
	matcher_attr.rule.num_log = rte_log2_u32(nb_flows);
	/* Build the item template. */
	for (i = 0; i < nb_item_templates; i++) {
		uint32_t ret;

		ret = __atomic_add_fetch(&item_templates[i]->refcnt, 1,
					 __ATOMIC_RELAXED);
		if (ret <= 1) {
			rte_errno = EINVAL;
			goto it_error;
		}
		mt[i] = item_templates[i]->mt;
		tbl->its[i] = item_templates[i];
	}
	tbl->matcher = mlx5dr_matcher_create
		(tbl->grp->tbl, mt, nb_item_templates, NULL, 0, &matcher_attr);
	if (!tbl->matcher)
		goto it_error;
	tbl->nb_item_templates = nb_item_templates;
	/* Build the action template. */
	for (i = 0; i < nb_action_templates; i++) {
		uint32_t ret;

		ret = __atomic_add_fetch(&action_templates[i]->refcnt, 1,
					 __ATOMIC_RELAXED);
		if (ret <= 1) {
			rte_errno = EINVAL;
			goto at_error;
		}
		LIST_INIT(&tbl->ats[i].acts.act_list);
		err = flow_hw_actions_translate(dev, attr,
						&tbl->ats[i].acts,
						action_templates[i], error);
		if (err) {
			i++;
			goto at_error;
		}
		tbl->ats[i].action_template = action_templates[i];
	}
	tbl->nb_action_templates = nb_action_templates;
	tbl->type = attr->flow_attr.transfer ? MLX5DR_TABLE_TYPE_FDB :
		    (attr->flow_attr.egress ? MLX5DR_TABLE_TYPE_NIC_TX :
		    MLX5DR_TABLE_TYPE_NIC_RX);
	LIST_INSERT_HEAD(&priv->flow_hw_tbl, tbl, next);
	return tbl;
at_error:
	while (i--) {
		__flow_hw_action_template_destroy(dev, &tbl->ats[i].acts);
		__atomic_sub_fetch(&action_templates[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	}
	i = nb_item_templates;
it_error:
	while (i--)
		__atomic_sub_fetch(&item_templates[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	mlx5dr_matcher_destroy(tbl->matcher);
error:
	err = rte_errno;
	if (tbl) {
		if (tbl->grp)
			mlx5_hlist_unregister(priv->sh->groups,
					      &tbl->grp->entry);
		if (tbl->flow)
			mlx5_ipool_destroy(tbl->flow);
		mlx5_free(tbl);
	}
	rte_flow_error_set(error, err,
			  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			  "fail to create rte table");
	return NULL;
}

/**
 * Destroy flow table.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] table
 *   Pointer to the table to be destroyed.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_table_destroy(struct rte_eth_dev *dev,
		      struct rte_flow_template_table *table,
		      struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int i;

	if (table->refcnt) {
		DRV_LOG(WARNING, "Table %p is still in using.", (void *)table);
		return rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "table in using");
	}
	LIST_REMOVE(table, next);
	for (i = 0; i < table->nb_item_templates; i++)
		__atomic_sub_fetch(&table->its[i]->refcnt,
				   1, __ATOMIC_RELAXED);
	for (i = 0; i < table->nb_action_templates; i++) {
		if (table->ats[i].acts.mark)
			flow_hw_rxq_flag_set(dev, false);
		__flow_hw_action_template_destroy(dev, &table->ats[i].acts);
		__atomic_sub_fetch(&table->ats[i].action_template->refcnt,
				   1, __ATOMIC_RELAXED);
	}
	mlx5dr_matcher_destroy(table->matcher);
	mlx5_hlist_unregister(priv->sh->groups, &table->grp->entry);
	mlx5_ipool_destroy(table->flow);
	mlx5_free(table);
	return 0;
}

static bool
flow_hw_modify_field_is_used(const struct rte_flow_action_modify_field *action,
			     enum rte_flow_field_id field)
{
	return action->src.field == field || action->dst.field == field;
}

static int
flow_hw_validate_action_modify_field(const struct rte_flow_action *action,
				     const struct rte_flow_action *mask,
				     struct rte_flow_error *error)
{
	const struct rte_flow_action_modify_field *action_conf =
		action->conf;
	const struct rte_flow_action_modify_field *mask_conf =
		mask->conf;

	if (action_conf->operation != mask_conf->operation)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modify_field operation mask and template are not equal");
	if (action_conf->dst.field != mask_conf->dst.field)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"destination field mask and template are not equal");
	if (action_conf->dst.field == RTE_FLOW_FIELD_POINTER ||
	    action_conf->dst.field == RTE_FLOW_FIELD_VALUE)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"immediate value and pointer cannot be used as destination");
	if (mask_conf->dst.level != UINT32_MAX)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION, action,
			"destination encapsulation level must be fully masked");
	if (mask_conf->dst.offset != UINT32_MAX)
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ACTION, action,
			"destination offset level must be fully masked");
	if (action_conf->src.field != mask_conf->src.field)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"destination field mask and template are not equal");
	if (action_conf->src.field != RTE_FLOW_FIELD_POINTER &&
	    action_conf->src.field != RTE_FLOW_FIELD_VALUE) {
		if (mask_conf->src.level != UINT32_MAX)
			return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"source encapsulation level must be fully masked");
		if (mask_conf->src.offset != UINT32_MAX)
			return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"source offset level must be fully masked");
	}
	if (mask_conf->width != UINT32_MAX)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modify_field width field must be fully masked");
	if (flow_hw_modify_field_is_used(action_conf, RTE_FLOW_FIELD_START))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modifying arbitrary place in a packet is not supported");
	if (flow_hw_modify_field_is_used(action_conf, RTE_FLOW_FIELD_VLAN_TYPE))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modifying vlan_type is not supported");
	if (flow_hw_modify_field_is_used(action_conf, RTE_FLOW_FIELD_GENEVE_VNI))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, action,
				"modifying Geneve VNI is not supported");
	return 0;
}

static int
flow_hw_action_validate(const struct rte_flow_action actions[],
			const struct rte_flow_action masks[],
			struct rte_flow_error *error)
{
	int i;
	bool actions_end = false;
	int ret;

	for (i = 0; !actions_end; ++i) {
		const struct rte_flow_action *action = &actions[i];
		const struct rte_flow_action *mask = &masks[i];

		if (action->type != mask->type)
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "mask type does not match action type");
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_INDIRECT:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_MARK:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_JUMP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_RSS:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_NVGRE_DECAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP:
			/* TODO: Validation logic */
			break;
		case RTE_FLOW_ACTION_TYPE_MODIFY_FIELD:
			ret = flow_hw_validate_action_modify_field(action,
									mask,
									error);
			if (ret < 0)
				return ret;
			break;
		case RTE_FLOW_ACTION_TYPE_END:
			actions_end = true;
			break;
		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action,
						  "action not supported in template API");
		}
	}
	return 0;
}

/**
 * Create flow action template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] attr
 *   Pointer to the action template attributes.
 * @param[in] actions
 *   Associated actions (list terminated by the END action).
 * @param[in] masks
 *   List of actions that marks which of the action's member is constant.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   Action template pointer on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_actions_template *
flow_hw_actions_template_create(struct rte_eth_dev *dev,
			const struct rte_flow_actions_template_attr *attr,
			const struct rte_flow_action actions[],
			const struct rte_flow_action masks[],
			struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	int len, act_len, mask_len, i;
	struct rte_flow_actions_template *at;

	if (flow_hw_action_validate(actions, masks, error))
		return NULL;
	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
				NULL, 0, actions, error);
	if (act_len <= 0)
		return NULL;
	len = RTE_ALIGN(act_len, 16);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS,
				 NULL, 0, masks, error);
	if (mask_len <= 0)
		return NULL;
	len += RTE_ALIGN(mask_len, 16);
	at = mlx5_malloc(MLX5_MEM_ZERO, len + sizeof(*at), 64, rte_socket_id());
	if (!at) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate action template");
		return NULL;
	}
	at->attr = *attr;
	at->actions = (struct rte_flow_action *)(at + 1);
	act_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->actions, len,
				actions, error);
	if (act_len <= 0)
		goto error;
	at->masks = (struct rte_flow_action *)
		    (((uint8_t *)at->actions) + act_len);
	mask_len = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, at->masks,
				 len - act_len, masks, error);
	if (mask_len <= 0)
		goto error;
	/*
	 * mlx5 PMD hacks indirect action index directly to the action conf.
	 * The rte_flow_conv() function copies the content from conf pointer.
	 * Need to restore the indirect action index from action conf here.
	 */
	for (i = 0; actions->type != RTE_FLOW_ACTION_TYPE_END;
	     actions++, masks++, i++) {
		if (actions->type == RTE_FLOW_ACTION_TYPE_INDIRECT) {
			at->actions[i].conf = actions->conf;
			at->masks[i].conf = masks->conf;
		}
	}
	__atomic_fetch_add(&at->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_at, at, next);
	return at;
error:
	mlx5_free(at);
	return NULL;
}

/**
 * Destroy flow action template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] template
 *   Pointer to the action template to be destroyed.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_actions_template_destroy(struct rte_eth_dev *dev __rte_unused,
				 struct rte_flow_actions_template *template,
				 struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1) {
		DRV_LOG(WARNING, "Action template %p is still in use.",
			(void *)template);
		return rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "action template in using");
	}
	LIST_REMOVE(template, next);
	mlx5_free(template);
	return 0;
}

/**
 * Create flow item template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] attr
 *   Pointer to the item template attributes.
 * @param[in] items
 *   The template item pattern.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *  Item template pointer on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_pattern_template *
flow_hw_pattern_template_create(struct rte_eth_dev *dev,
			     const struct rte_flow_pattern_template_attr *attr,
			     const struct rte_flow_item items[],
			     struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_pattern_template *it;

	it = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*it), 0, rte_socket_id());
	if (!it) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate item template");
		return NULL;
	}
	it->attr = *attr;
	it->mt = mlx5dr_match_template_create(items, attr->relaxed_matching);
	if (!it->mt) {
		mlx5_free(it);
		rte_flow_error_set(error, rte_errno,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot create match template");
		return NULL;
	}
	it->item_flags = flow_hw_rss_item_flags_get(items);
	__atomic_fetch_add(&it->refcnt, 1, __ATOMIC_RELAXED);
	LIST_INSERT_HEAD(&priv->flow_hw_itt, it, next);
	return it;
}

/**
 * Destroy flow item template.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] template
 *   Pointer to the item template to be destroyed.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_pattern_template_destroy(struct rte_eth_dev *dev __rte_unused,
			      struct rte_flow_pattern_template *template,
			      struct rte_flow_error *error __rte_unused)
{
	if (__atomic_load_n(&template->refcnt, __ATOMIC_RELAXED) > 1) {
		DRV_LOG(WARNING, "Item template %p is still in use.",
			(void *)template);
		return rte_flow_error_set(error, EBUSY,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "item template in using");
	}
	LIST_REMOVE(template, next);
	claim_zero(mlx5dr_match_template_destroy(template->mt));
	mlx5_free(template);
	return 0;
}

/*
 * Get information about HWS pre-configurable resources.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[out] port_info
 *   Pointer to port information.
 * @param[out] queue_info
 *   Pointer to queue information.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */
static int
flow_hw_info_get(struct rte_eth_dev *dev __rte_unused,
		 struct rte_flow_port_info *port_info __rte_unused,
		 struct rte_flow_queue_info *queue_info __rte_unused,
		 struct rte_flow_error *error __rte_unused)
{
	/* Nothing to be updated currently. */
	memset(port_info, 0, sizeof(*port_info));
	/* Queue size is unlimited from low-level. */
	queue_info->max_size = UINT32_MAX;
	return 0;
}

/**
 * Create group callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] cb_ctx
 *   Pointer to the group creation context.
 *
 * @return
 *   Group entry on success, NULL otherwise and rte_errno is set.
 */
struct mlx5_list_entry *
flow_hw_grp_create_cb(void *tool_ctx, void *cb_ctx)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct rte_eth_dev *dev = ctx->dev;
	struct rte_flow_attr *attr = (struct rte_flow_attr *)ctx->data;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_table_attr dr_tbl_attr = {0};
	struct rte_flow_error *error = ctx->error;
	struct mlx5_flow_group *grp_data;
	struct mlx5dr_table *tbl = NULL;
	struct mlx5dr_action *jump;
	uint32_t idx = 0;

	grp_data = mlx5_ipool_zmalloc(sh->ipool[MLX5_IPOOL_HW_GRP], &idx);
	if (!grp_data) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate flow table data entry");
		return NULL;
	}
	dr_tbl_attr.level = attr->group;
	if (attr->transfer)
		dr_tbl_attr.type = MLX5DR_TABLE_TYPE_FDB;
	else if (attr->egress)
		dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_TX;
	else
		dr_tbl_attr.type = MLX5DR_TABLE_TYPE_NIC_RX;
	tbl = mlx5dr_table_create(priv->dr_ctx, &dr_tbl_attr);
	if (!tbl)
		goto error;
	grp_data->tbl = tbl;
	if (attr->group) {
		/* Jump action be used by non-root table. */
		jump = mlx5dr_action_create_dest_table
			(priv->dr_ctx, tbl,
			 mlx5_hw_act_flag[!!attr->group][dr_tbl_attr.type]);
		if (!jump)
			goto error;
		grp_data->jump.hws_action = jump;
		/* Jump action be used by root table.  */
		jump = mlx5dr_action_create_dest_table
			(priv->dr_ctx, tbl,
			 mlx5_hw_act_flag[MLX5_HW_ACTION_FLAG_ROOT]
					 [dr_tbl_attr.type]);
		if (!jump)
			goto error;
		grp_data->jump.root_action = jump;
	}
	grp_data->idx = idx;
	grp_data->group_id = attr->group;
	grp_data->type = dr_tbl_attr.type;
	return &grp_data->entry;
error:
	if (grp_data->jump.root_action)
		mlx5dr_action_destroy(grp_data->jump.root_action);
	if (grp_data->jump.hws_action)
		mlx5dr_action_destroy(grp_data->jump.hws_action);
	if (tbl)
		mlx5dr_table_destroy(tbl);
	if (idx)
		mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], idx);
	rte_flow_error_set(error, ENOMEM,
			   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			   NULL,
			   "cannot allocate flow dr table");
	return NULL;
}

/**
 * Remove group callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the entry to be removed.
 */
void
flow_hw_grp_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_group *grp_data =
		    container_of(entry, struct mlx5_flow_group, entry);

	MLX5_ASSERT(entry && sh);
	/* To use the wrapper glue functions instead. */
	if (grp_data->jump.hws_action)
		mlx5dr_action_destroy(grp_data->jump.hws_action);
	if (grp_data->jump.root_action)
		mlx5dr_action_destroy(grp_data->jump.root_action);
	mlx5dr_table_destroy(grp_data->tbl);
	mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], grp_data->idx);
}

/**
 * Match group callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the group to be matched.
 * @param[in] cb_ctx
 *   Pointer to the group matching context.
 *
 * @return
 *   0 on matched, 1 on miss matched.
 */
int
flow_hw_grp_match_cb(void *tool_ctx __rte_unused, struct mlx5_list_entry *entry,
		     void *cb_ctx)
{
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_group *grp_data =
		container_of(entry, struct mlx5_flow_group, entry);
	struct rte_flow_attr *attr =
			(struct rte_flow_attr *)ctx->data;

	return (grp_data->group_id != attr->group) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_FDB) &&
		attr->transfer) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_NIC_TX) &&
		attr->egress) ||
		((grp_data->type != MLX5DR_TABLE_TYPE_NIC_RX) &&
		attr->ingress);
}

/**
 * Clone group entry callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the group to be matched.
 * @param[in] cb_ctx
 *   Pointer to the group matching context.
 *
 * @return
 *   0 on matched, 1 on miss matched.
 */
struct mlx5_list_entry *
flow_hw_grp_clone_cb(void *tool_ctx, struct mlx5_list_entry *oentry,
		     void *cb_ctx)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_cb_ctx *ctx = cb_ctx;
	struct mlx5_flow_group *grp_data;
	struct rte_flow_error *error = ctx->error;
	uint32_t idx = 0;

	grp_data = mlx5_ipool_malloc(sh->ipool[MLX5_IPOOL_HW_GRP], &idx);
	if (!grp_data) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   NULL,
				   "cannot allocate flow table data entry");
		return NULL;
	}
	memcpy(grp_data, oentry, sizeof(*grp_data));
	grp_data->idx = idx;
	return &grp_data->entry;
}

/**
 * Free cloned group entry callback.
 *
 * @param[in] tool_ctx
 *   Pointer to the hash list related context.
 * @param[in] entry
 *   Pointer to the group to be freed.
 */
void
flow_hw_grp_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry)
{
	struct mlx5_dev_ctx_shared *sh = tool_ctx;
	struct mlx5_flow_group *grp_data =
		    container_of(entry, struct mlx5_flow_group, entry);

	mlx5_ipool_free(sh->ipool[MLX5_IPOOL_HW_GRP], grp_data->idx);
}

/**
 * Configure port HWS resources.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] port_attr
 *   Port configuration attributes.
 * @param[in] nb_queue
 *   Number of queue.
 * @param[in] queue_attr
 *   Array that holds attributes for each flow queue.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, a negative errno value otherwise and rte_errno is set.
 */

static int
flow_hw_configure(struct rte_eth_dev *dev,
		  const struct rte_flow_port_attr *port_attr,
		  uint16_t nb_queue,
		  const struct rte_flow_queue_attr *queue_attr[],
		  struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5dr_context *dr_ctx = NULL;
	struct mlx5dr_context_attr dr_ctx_attr = {0};
	struct mlx5_hw_q *hw_q;
	struct mlx5_hw_q_job *job = NULL;
	uint32_t mem_size, i, j;
	struct mlx5_indexed_pool_config cfg = {
		.size = sizeof(struct mlx5_action_construct_data),
		.trunk_size = 4096,
		.need_lock = 1,
		.release_mem_en = !!priv->sh->config.reclaim_mode,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
		.type = "mlx5_hw_action_construct_data",
	};

	if (!port_attr || !nb_queue || !queue_attr) {
		rte_errno = EINVAL;
		goto err;
	}
	/* In case re-configuring, release existing context at first. */
	if (priv->dr_ctx) {
		/* */
		for (i = 0; i < nb_queue; i++) {
			hw_q = &priv->hw_q[i];
			/* Make sure all queues are empty. */
			if (hw_q->size != hw_q->job_idx) {
				rte_errno = EBUSY;
				goto err;
			}
		}
		flow_hw_resource_release(dev);
	}
	priv->acts_ipool = mlx5_ipool_create(&cfg);
	if (!priv->acts_ipool)
		goto err;
	/* Allocate the queue job descriptor LIFO. */
	mem_size = sizeof(priv->hw_q[0]) * nb_queue;
	for (i = 0; i < nb_queue; i++) {
		/*
		 * Check if the queues' size are all the same as the
		 * limitation from HWS layer.
		 */
		if (queue_attr[i]->size != queue_attr[0]->size) {
			rte_errno = EINVAL;
			goto err;
		}
		mem_size += (sizeof(struct mlx5_hw_q_job *) +
			    sizeof(uint8_t) * MLX5_ENCAP_MAX_LEN +
			    sizeof(struct mlx5_modification_cmd) *
			    MLX5_MHDR_MAX_CMD +
			    sizeof(struct mlx5_hw_q_job)) *
			    queue_attr[0]->size;
	}
	priv->hw_q = mlx5_malloc(MLX5_MEM_ZERO, mem_size,
				 64, SOCKET_ID_ANY);
	if (!priv->hw_q) {
		rte_errno = ENOMEM;
		goto err;
	}
	for (i = 0; i < nb_queue; i++) {
		uint8_t *encap = NULL;
		struct mlx5_modification_cmd *mhdr_cmd = NULL;

		priv->hw_q[i].job_idx = queue_attr[i]->size;
		priv->hw_q[i].size = queue_attr[i]->size;
		if (i == 0)
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
					    &priv->hw_q[nb_queue];
		else
			priv->hw_q[i].job = (struct mlx5_hw_q_job **)
					    &job[queue_attr[i - 1]->size];
		job = (struct mlx5_hw_q_job *)
		      &priv->hw_q[i].job[queue_attr[i]->size];
		mhdr_cmd = (struct mlx5_modification_cmd *)&job[queue_attr[i]->size];
		encap = (uint8_t *)&mhdr_cmd[queue_attr[i]->size * MLX5_MHDR_MAX_CMD];
		for (j = 0; j < queue_attr[i]->size; j++) {
			job[j].mhdr_cmd = &mhdr_cmd[j * MLX5_MHDR_MAX_CMD];
			job[j].encap_data = &encap[j * MLX5_ENCAP_MAX_LEN];
			priv->hw_q[i].job[j] = &job[j];
		}
	}
	dr_ctx_attr.pd = priv->sh->cdev->pd;
	dr_ctx_attr.queues = nb_queue;
	/* Queue size should all be the same. Take the first one. */
	dr_ctx_attr.queue_size = queue_attr[0]->size;
	dr_ctx = mlx5dr_context_open(priv->sh->cdev->ctx, &dr_ctx_attr);
	/* rte_errno has been updated by HWS layer. */
	if (!dr_ctx)
		goto err;
	priv->dr_ctx = dr_ctx;
	priv->nb_queue = nb_queue;
	/* Add global actions. */
	for (i = 0; i < MLX5_HW_ACTION_FLAG_MAX; i++) {
		for (j = 0; j < MLX5DR_TABLE_TYPE_MAX; j++) {
			priv->hw_drop[i][j] = mlx5dr_action_create_dest_drop
				(priv->dr_ctx, mlx5_hw_act_flag[i][j]);
			if (!priv->hw_drop[i][j])
				goto err;
		}
		priv->hw_tag[i] = mlx5dr_action_create_tag
			(priv->dr_ctx, mlx5_hw_act_flag[i][0]);
		if (!priv->hw_tag[i])
			goto err;
	}
	return 0;
err:
	for (i = 0; i < MLX5_HW_ACTION_FLAG_MAX; i++) {
		for (j = 0; j < MLX5DR_TABLE_TYPE_MAX; j++) {
			if (priv->hw_drop[i][j])
				mlx5dr_action_destroy(priv->hw_drop[i][j]);
		}
		if (priv->hw_tag[i])
			mlx5dr_action_destroy(priv->hw_tag[i]);
	}
	if (dr_ctx)
		claim_zero(mlx5dr_context_close(dr_ctx));
	mlx5_free(priv->hw_q);
	priv->hw_q = NULL;
	if (priv->acts_ipool) {
		mlx5_ipool_destroy(priv->acts_ipool);
		priv->acts_ipool = NULL;
	}
	return rte_flow_error_set(error, rte_errno,
				  RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				  "fail to configure port");
}

/**
 * Release HWS resources.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
void
flow_hw_resource_release(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_template_table *tbl;
	struct rte_flow_pattern_template *it;
	struct rte_flow_actions_template *at;
	int i, j;

	if (!priv->dr_ctx)
		return;
	while (!LIST_EMPTY(&priv->flow_hw_tbl)) {
		tbl = LIST_FIRST(&priv->flow_hw_tbl);
		flow_hw_table_destroy(dev, tbl, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_itt)) {
		it = LIST_FIRST(&priv->flow_hw_itt);
		flow_hw_pattern_template_destroy(dev, it, NULL);
	}
	while (!LIST_EMPTY(&priv->flow_hw_at)) {
		at = LIST_FIRST(&priv->flow_hw_at);
		flow_hw_actions_template_destroy(dev, at, NULL);
	}
	for (i = 0; i < MLX5_HW_ACTION_FLAG_MAX; i++) {
		for (j = 0; j < MLX5DR_TABLE_TYPE_MAX; j++) {
			if (priv->hw_drop[i][j])
				mlx5dr_action_destroy(priv->hw_drop[i][j]);
		}
		if (priv->hw_tag[i])
			mlx5dr_action_destroy(priv->hw_tag[i]);
	}
	if (priv->acts_ipool) {
		mlx5_ipool_destroy(priv->acts_ipool);
		priv->acts_ipool = NULL;
	}
	mlx5_free(priv->hw_q);
	priv->hw_q = NULL;
	claim_zero(mlx5dr_context_close(priv->dr_ctx));
	priv->dr_ctx = NULL;
	priv->nb_queue = 0;
}

/* Sets vport tag and mask, for given port, used in HWS rules. */
void
flow_hw_set_port_info(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint16_t port_id = dev->data->port_id;
	struct flow_hw_port_info *info;

	MLX5_ASSERT(port_id < RTE_MAX_ETHPORTS);
	info = &mlx5_flow_hw_port_infos[port_id];
	info->regc_mask = priv->vport_meta_mask;
	info->regc_value = priv->vport_meta_tag;
	info->is_wire = priv->master;
}

/* Clears vport tag and mask used for HWS rules. */
void
flow_hw_clear_port_info(struct rte_eth_dev *dev)
{
	uint16_t port_id = dev->data->port_id;
	struct flow_hw_port_info *info;

	MLX5_ASSERT(port_id < RTE_MAX_ETHPORTS);
	info = &mlx5_flow_hw_port_infos[port_id];
	info->regc_mask = 0;
	info->regc_value = 0;
	info->is_wire = 0;
}

/*
 * Initialize the information of available tag registers and an intersection
 * of all the probed devices' REG_C_Xs.
 * PS. No port concept in steering part, right now it cannot be per port level.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
void flow_hw_init_tags_set(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	uint32_t meta_mode = priv->sh->config.dv_xmeta_en;
	uint8_t masks = (uint8_t)priv->sh->cdev->config.hca_attr.set_reg_c;
	uint32_t i, j;
	enum modify_reg copy[MLX5_FLOW_HW_TAGS_MAX] = {REG_NON};
	uint8_t unset = 0;
	uint8_t copy_masks = 0;

	/*
	 * The CAPA is global for common device but only used in net.
	 * It is shared per eswitch domain.
	 */
	if (!!priv->sh->hws_tags)
		return;
	unset |= 1 << (priv->mtr_color_reg - REG_C_0);
	unset |= 1 << (REG_C_6 - REG_C_0);
	if (meta_mode == MLX5_XMETA_MODE_META32_HWS) {
		unset |= 1 << (REG_C_1 - REG_C_0);
		unset |= 1 << (REG_C_0 - REG_C_0);
	}
	masks &= ~unset;
	if (mlx5_flow_hw_avl_tags_init_cnt) {
		for (i = 0; i < MLX5_FLOW_HW_TAGS_MAX; i++) {
			if (mlx5_flow_hw_avl_tags[i] != REG_NON && !!((1 << i) & masks)) {
				copy[mlx5_flow_hw_avl_tags[i] - REG_C_0] =
						mlx5_flow_hw_avl_tags[i];
				copy_masks |= (1 << i);
			}
		}
		if (copy_masks != masks) {
			j = 0;
			for (i = 0; i < MLX5_FLOW_HW_TAGS_MAX; i++)
				if (!!((1 << i) & copy_masks))
					mlx5_flow_hw_avl_tags[j++] = copy[i];
		}
	} else {
		j = 0;
		for (i = 0; i < MLX5_FLOW_HW_TAGS_MAX; i++) {
			if (!!((1 << i) & masks))
				mlx5_flow_hw_avl_tags[j++] =
					(enum modify_reg)(i + (uint32_t)REG_C_0);
		}
	}
	priv->sh->hws_tags = 1;
	mlx5_flow_hw_avl_tags_init_cnt++;
}

/*
 * Reset the available tag registers information to NONE.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 */
void flow_hw_clear_tags_set(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;

	if (!priv->sh->hws_tags)
		return;
	priv->sh->hws_tags = 0;
	mlx5_flow_hw_avl_tags_init_cnt--;
	if (!mlx5_flow_hw_avl_tags_init_cnt)
		memset(mlx5_flow_hw_avl_tags, REG_NON,
		       sizeof(enum modify_reg) * MLX5_FLOW_HW_TAGS_MAX);
}

/**
 * Create shared action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   Which queue to be used..
 * @param[in] attr
 *   Operation attribute.
 * @param[in] conf
 *   Indirect action configuration.
 * @param[in] action
 *   rte_flow action detail.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   Action handle on success, NULL otherwise and rte_errno is set.
 */
static struct rte_flow_action_handle *
flow_hw_action_handle_create(struct rte_eth_dev *dev, uint32_t queue,
			     const struct rte_flow_op_attr *attr,
			     const struct rte_flow_indir_action_conf *conf,
			     const struct rte_flow_action *action,
			     void *user_data,
			     struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	RTE_SET_USED(user_data);
	return flow_dv_action_create(dev, conf, action, error);
}

/**
 * Update shared action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   Which queue to be used..
 * @param[in] attr
 *   Operation attribute.
 * @param[in] handle
 *   Action handle to be updated.
 * @param[in] update
 *   Update value.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_action_handle_update(struct rte_eth_dev *dev, uint32_t queue,
			     const struct rte_flow_op_attr *attr,
			     struct rte_flow_action_handle *handle,
			     const void *update,
			     void *user_data,
			     struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	RTE_SET_USED(user_data);
	return flow_dv_action_update(dev, handle, update, error);
}

/**
 * Destroy shared action.
 *
 * @param[in] dev
 *   Pointer to the rte_eth_dev structure.
 * @param[in] queue
 *   Which queue to be used..
 * @param[in] attr
 *   Operation attribute.
 * @param[in] handle
 *   Action handle to be destroyed.
 * @param[in] user_data
 *   Pointer to the user_data.
 * @param[out] error
 *   Pointer to error structure.
 *
 * @return
 *   0 on success, negative value otherwise and rte_errno is set.
 */
static int
flow_hw_action_handle_destroy(struct rte_eth_dev *dev, uint32_t queue,
			      const struct rte_flow_op_attr *attr,
			      struct rte_flow_action_handle *handle,
			      void *user_data,
			      struct rte_flow_error *error)
{
	RTE_SET_USED(queue);
	RTE_SET_USED(attr);
	RTE_SET_USED(user_data);
	return flow_dv_action_destroy(dev, handle, error);
}


const struct mlx5_flow_driver_ops mlx5_flow_hw_drv_ops = {
	.info_get = flow_hw_info_get,
	.configure = flow_hw_configure,
	.pattern_template_create = flow_hw_pattern_template_create,
	.pattern_template_destroy = flow_hw_pattern_template_destroy,
	.actions_template_create = flow_hw_actions_template_create,
	.actions_template_destroy = flow_hw_actions_template_destroy,
	.template_table_create = flow_hw_table_create,
	.template_table_destroy = flow_hw_table_destroy,
	.async_flow_create = flow_hw_async_flow_create,
	.async_flow_destroy = flow_hw_async_flow_destroy,
	.pull = flow_hw_pull,
	.push = flow_hw_push,
	.async_action_create = flow_hw_action_handle_create,
	.async_action_destroy = flow_hw_action_handle_destroy,
	.async_action_update = flow_hw_action_handle_update,
	.action_validate = flow_dv_action_validate,
	.action_create = flow_dv_action_create,
	.action_destroy = flow_dv_action_destroy,
	.action_update = flow_dv_action_update,
	.action_query = flow_dv_action_query,
};

#endif
