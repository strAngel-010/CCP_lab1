#!/usr/bin/env python3
import argparse
import socket
import time
import random
import string

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Receiver (P2 + злоумышленник)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--n', type=int, default=10, help='Parameter n (must match sender)')
    parser.add_argument('--L', type=int, default=1500, help='Max packet length')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Listen host')
    parser.add_argument('--port', type=int, default=12345, help='UDP port')
    
    return parser.parse_args()

def get_alphabet(K: int) -> str:    
    if K >= 98:
        specials = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n «»"
        return string.digits + string.ascii_letters + specials
    elif K >= 62: return string.ascii_letters + string.digits
    elif K >= 36: return string.digits + string.ascii_lowercase
    else: return string.digits

def decode_length_to_symbol(length: int, n: int, L: int) -> int:
    symbol_id = (length - 1) // n
    K = L // n
    return min(symbol_id, K - 1)

def symbol_to_char(symbol_id: int, K: int) -> str:
    alphabet = get_alphabet(K)
    if symbol_id < len(alphabet):
        return alphabet[symbol_id]
    else:
        return '?'

def receiver_loop(args: argparse.Namespace):
    random.seed(time.time())
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    
    K = args.L // args.n
    alphabet = get_alphabet(K)
    print(f"Listening MARKER packets on {args.host}:{args.port}")
    print(f"n={args.n}, L={args.L}, K={K}, alphabet: {alphabet[:30]}{'...' if len(alphabet)>30 else ''}")
    
    packets = 0
    secrets = 0
    secret_symbols = []
    decoded_message = []
    
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            if len(data) < 8:
                continue
            
            marked_seq_id = int.from_bytes(data[:4], 'big')
            pkt_length = int.from_bytes(data[4:8], 'big')
            
            marker = marked_seq_id & 1
            seq_id_display = marked_seq_id >> 1
            
            packets += 1
            
            if marker == 1:
                symbol_id = decode_length_to_symbol(pkt_length, args.n, args.L)
                secret_symbols.append(symbol_id)
                char = symbol_to_char(symbol_id, K)
                decoded_message.append(char)
                secrets += 1
                
                print(f"P#{seq_id_display} MARKER=1 [{addr}]: "
                      f"len={pkt_length} -> sym={symbol_id} '{char}' "
                      f"(secrets={secrets}/{packets})")
                
                if secrets % 5 == 0:
                    recent = ''.join(decoded_message[-15:])
                    print(f"  DECODED so far: '...{recent}'")
            else:
                print(f"P#{seq_id_display} MARKER=0 [{addr}]: dummy len={pkt_length}")
    
    except KeyboardInterrupt:
        print("\n--- STOPPED ---")
    finally:
        sock.close()
    
    if secret_symbols:
        final_message = ''.join(decoded_message)
        print(f"\n{'='*50}")
        print(f"*** DECODE: '{final_message}' ***")
        print(f"Stats: {secrets}/{packets} secret packets")
        print(f"Alphabet used: {get_alphabet(K)}")
        print(f"{'='*50}")

def main():
    args = parse_arguments()
    receiver_loop(args)

if __name__ == "__main__":
    main()
