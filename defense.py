#!/usr/bin/env python3
import argparse
import socket
import random
import time


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Defense node for LR3',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--listen-host', type=str, default='0.0.0.0',
                        help='Host to listen on')
    parser.add_argument('--listen-port', type=int, default=12345,
                        help='UDP port to listen on')

    parser.add_argument('--forward-host', type=str, required=True,
                        help='Listener host to forward packets to')
    parser.add_argument('--forward-port', type=int, default=12345,
                        help='Listener UDP port')

    parser.add_argument('--mode', choices=['pass', 'limit', 'block'],
                        default='pass',
                        help='Defense mode')

    parser.add_argument('--L', type=int, default=1500,
                        help='Maximum payload length')
    parser.add_argument('--q', type=int, default=50,
                        help='Quantization step for limit mode')
    parser.add_argument('--fixed-len', type=int, default=256,
                        help='Fixed payload length for block mode')

    return parser.parse_args()


def random_bytes(count: int) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(count))


def rebuild_packet(marked_seq_id: int, payload: bytes) -> bytes:
    pkt_length = len(payload)
    header = marked_seq_id.to_bytes(4, 'big') + pkt_length.to_bytes(4, 'big')
    return header + payload


def apply_limit_mode(payload: bytes, q: int, L: int) -> bytes:
    old_length = len(payload)

    # Округление вверх до ближайшего кратного q
    new_length = ((old_length + q - 1) // q) * q
    new_length = min(new_length, L)

    if new_length > old_length:
        payload = payload + random_bytes(new_length - old_length)
    elif new_length < old_length:
        payload = payload[:new_length]

    return payload


def split_into_blocks(payload: bytes, block_size: int) -> list[bytes]:
    blocks = []

    for i in range(0, len(payload), block_size):
        chunk = payload[i:i + block_size]
        if len(chunk) < block_size:
            chunk = chunk + b'\x00' * (block_size - len(chunk))
        blocks.append(chunk)

    if not blocks:
        blocks.append(b'\x00' * block_size)

    return blocks

def defense_loop(args: argparse.Namespace):
    random.seed(time.time())

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((args.listen_host, args.listen_port))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_addr = (args.forward_host, args.forward_port)

    print(f"Defense started on {args.listen_host}:{args.listen_port}")
    print(f"Forwarding to {args.forward_host}:{args.forward_port}")
    print(f"Mode: {args.mode}")

    try:
        while True:
            data, addr = recv_sock.recvfrom(65535)

            if len(data) < 8:
                continue

            marked_seq_id = int.from_bytes(data[:4], 'big')
            pkt_length = int.from_bytes(data[4:8], 'big')
            payload = data[8:]

            real_length = len(payload)
            if real_length < pkt_length:
                continue

            payload = payload[:pkt_length]

            old_marker = marked_seq_id & 1
            seq_id = marked_seq_id >> 1

            if args.mode == 'pass':
                new_marked_seq_id = marked_seq_id
                new_payload = payload

            elif args.mode == 'limit':
                new_marked_seq_id = marked_seq_id
                new_payload = apply_limit_mode(payload, args.q, args.L)

            elif args.mode == 'block':
                blocks = split_into_blocks(payload, args.fixed_len)
                original_marked_seq_id = data[:4]

                for block_index, block in enumerate(blocks):
                    new_pkt_length = len(block).to_bytes(4, 'big')
                    new_header = original_marked_seq_id + new_pkt_length
                    packet = new_header + block
                    send_sock.sendto(packet, forward_addr)

                    print(
                        f"from={addr} seq={seq_id} marker:{old_marker}->{old_marker} "
                        f"orig_len={pkt_length} block_len={len(block)} "
                        f"block {block_index + 1}/{len(blocks)}"
                    )

                continue

            packet = rebuild_packet(new_marked_seq_id, new_payload)
            send_sock.sendto(packet, forward_addr)

            new_marker = new_marked_seq_id & 1
            print(
                f"from={addr} seq={seq_id} marker:{old_marker}->{new_marker} "
                f"len:{pkt_length}->{len(new_payload)}"
            )

    except KeyboardInterrupt:
        print("\nDefense stopped.")
    finally:
        recv_sock.close()
        send_sock.close()


def main():
    args = parse_arguments()
    defense_loop(args)


if __name__ == '__main__':
    main()