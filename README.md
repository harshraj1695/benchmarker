# DPDK AF_PACKET Benchmark

This tool helps you compare DPDK apps when you do not have a physical NIC.

It uses:

- one Linux `veth` pair
- one network namespace
- one AF_PACKET DPDK port
- raw packet generation from the namespace side

## File

- `tools/dpdk_afpacket_bench.py`

## Main Idea

This is a general AF_PACKET benchmark tool.

If your DPDK app:

- uses `--vdev=net_af_packet...`
- receives packets
- transmits packets back out

then this tool can benchmark it.

## What It Measures

- packets sent
- packets received back
- packet loss
- send pps
- return pps
- goodput Mbps
- app CPU percent
- app RSS memory

## Run

Use root because it creates a network namespace and raw sockets:

```bash
sudo python3 tools/dpdk_afpacket_bench.py \
  --app "myapp::/path/to/app --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}"
```

`{iface}` is replaced by the temporary AF_PACKET test interface created by the tool.

Important:

- pass the built binary, not the source directory
- use `iface={iface}`, not `iface=eth0`
- `--pps` and `--count` are benchmark tool options, so keep them outside the quoted app command

Correct style:

```bash
sudo python3 tools/dpdk_afpacket_bench.py \
  --app "packet_parsing::/home/harshraj1695/dpdk/ports/packet_parsing/packet_parsing --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}" \
  --pps 50000 \
  --count 10000
```

## Compare Two Apps

```bash
sudo python3 tools/dpdk_afpacket_bench.py \
  --app "parser::/path/to/parser_app --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}" \
  --app "firewall::/path/to/firewall_app --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}"
```

## Send Input To App

If your app needs CLI text after startup:

```bash
sudo python3 tools/dpdk_afpacket_bench.py \
  --app "graphfw::/path/to/graphfw --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}" \
  --stdin-text "enable firewall\n"
```

## Rate Control

```bash
sudo python3 tools/dpdk_afpacket_bench.py \
  --app "myapp::/path/to/app --no-huge -l 0-1 --vdev=net_af_packet0,iface={iface}" \
  --pps 50000 \
  --count 100000
```

## Notes

- it assumes your app binary already exists
- it assumes the app can run with `--vdev=net_af_packet0,iface=<iface>` or equivalent
- it compares with the same Linux-only setup, so results are fair even without a NIC
- the current measurement is best for apps that receive packets and transmit them back out
- `send_pps` is generator speed
- `return_pps` and `goodput_mbps` show actual app forwarding performance
