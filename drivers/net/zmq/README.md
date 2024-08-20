# DPDK ZeroMQ driver

Driver must have one "pub" device and one "sub". Each of the devices polls socket on server core. Sub device polls socket and distributes packets between queues by hash of src_addr and dst_addr. On pub device each queue sends packets to a single mp/mc ring which are consumed by tx service core and sent over zmq 

Example:
```bash
sudo ./build/app/dpdk-testpmd -l 0-5 -n 4 -s 1 \
	--vdev=net_zmq0,endpoint=tcp://localhost:8080,method=bind,rx_lcore_id=4,rx_ring_size=512,type=sub \
	--vdev=net_zmq1,endpoint=tcp://localhost:8000,method=connect,tx_lcore_id=5,tx_ring_size=512,type=pub \
	-- --port-topology=paired --rxq 2 --txq 2 --nb-cores=2 -a
```

## Virtual device flag options

* endpoit: ZeroMQ url 
* method: bind/connect to the port 
* (rx/tx)_lcore_id: Lcore id to run socket service core on
* tx_ring_size: Size of a single tx ring for all queues. Must be power of 2
* rx_ring_size: Size of rx ring per queue. Must be power of 2
* type: ZeroMQ socket type. Only pub and sub are supported

## Notes

* Topology must be "paired" or because one port can only receive and other can only send
* Polling service core will interfere with other services if assigned to the same lcore
