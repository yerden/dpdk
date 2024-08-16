# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 Yerden Zhumabekov

if not dpdk_conf.has('RTE_HAS_LIBZMQ')
    build = false
    reason = 'missing dependency, "libzmq"'
endif

sources = files(
        'rte_eth_zmq.c',
)

ext_deps += zmq_dep

deps += ['hash']
