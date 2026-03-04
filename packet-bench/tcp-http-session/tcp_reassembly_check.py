#!/usr/bin/env python3
"""TCP handshake + stream reassembly checks for HTTP GET traffic via tshark."""

from __future__ import annotations
import subprocess


def _run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout or ''


def analyze_tcp_http_pcap(pcap_path: str, server_port: int = 18080) -> dict:
    try:
        # Count SYN, SYN/ACK, and ACK packets for server port traffic.
        syn = _run(['tshark', '-r', pcap_path, '-Y', f'tcp.dstport == {server_port} && tcp.flags.syn == 1 && tcp.flags.ack == 0', '-T', 'fields', '-e', 'frame.number'])
        synack = _run(['tshark', '-r', pcap_path, '-Y', f'tcp.srcport == {server_port} && tcp.flags.syn == 1 && tcp.flags.ack == 1', '-T', 'fields', '-e', 'frame.number'])
        ack = _run(['tshark', '-r', pcap_path, '-Y', f'tcp.dstport == {server_port} && tcp.flags.syn == 0 && tcp.flags.ack == 1', '-T', 'fields', '-e', 'frame.number'])

        syn_n = len([x for x in syn.splitlines() if x.strip()])
        synack_n = len([x for x in synack.splitlines() if x.strip()])
        ack_n = len([x for x in ack.splitlines() if x.strip()])

        # Reassembled HTTP views from tshark dissector.
        get_out = _run(['tshark', '-r', pcap_path, '-Y', f'http.request.method == "GET" && tcp.dstport == {server_port}', '-T', 'fields', '-e', 'tcp.stream'])
        ok_out = _run(['tshark', '-r', pcap_path, '-Y', f'http.response.code == 200 && tcp.srcport == {server_port}', '-T', 'fields', '-e', 'tcp.stream'])

        get_streams = {x.strip() for x in get_out.splitlines() if x.strip()}
        ok_streams = {x.strip() for x in ok_out.splitlines() if x.strip()}

        return {
            'tcp_syn_packets': syn_n,
            'tcp_synack_packets': synack_n,
            'tcp_ack_packets': ack_n,
            'tcp_handshake_estimate': min(syn_n, synack_n, ack_n),
            'http_get_streams_after_reassembly': len(get_streams),
            'http_200_streams_after_reassembly': len(ok_streams),
        }
    except Exception as e:
        return {'error': str(e)}
