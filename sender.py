#!/usr/bin/env python3
import argparse
import random
import time
import socket
import threading
import queue
from typing import List
import string

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Sender (P1 + закладка)',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--message', type=str, help='Secret message string')
    group.add_argument('--file', type=str, help='Path to secret file')
    
    parser.add_argument('--n', type=int, default=10, help='Parameter n for channel (range size)')
    parser.add_argument('--L', type=int, default=1500, help='Max packet length (bytes)')
    parser.add_argument('--t', type=float, default=1.0, help='Fixed send interval (sec)')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Receiver host')
    parser.add_argument('--port', type=int, default=12345, help='UDP port')
    parser.add_argument('--duration', type=int, default=60, help='Run duration (sec)')
    parser.add_argument('--buffer_size', type=int, default=10, help='Secret buffer size (symbols)')
    
    return parser.parse_args()

def get_alphabet(K: int) -> str:    
    if K >= 98:
        specials = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\n «»"
        return string.digits + string.ascii_letters + specials
    elif K >= 62: return string.ascii_letters + string.digits
    elif K >= 36: return string.digits + string.ascii_lowercase
    else: return string.digits

def load_secret_message(args: argparse.Namespace) -> str:
    if args.message:
        return args.message
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

def message_to_symbols(message: str, n: int, L: int) -> List[int]:
    K = L // n
    alphabet = get_alphabet(K)
    
    print(f"Using alphabet size: {len(alphabet)} (K={K})")
    char_to_id = {char: idx for idx, char in enumerate(alphabet)}
    
    symbols = []
    for char in message:
        if char in char_to_id:
            symbols.append(char_to_id[char])
        else:
            symbols.append(0)
            print(f"  '{char}' → 0 (not in alphabet)")
    
    return symbols

def encode_symbol(symbol_id: int, n: int, L: int) -> int:
    K = L // n
    symbol_id = min(symbol_id, K - 1)
    
    low = symbol_id * n + 1
    high = min((symbol_id + 1) * n, L)
    
    if high < low:
        print(f"ERROR: empty range! symbol_id={symbol_id}, low={low}, high={high}")
        return dummy_length(L)
    
    random.seed(time.time())
    return random.randint(low, high)

def dummy_length(L: int) -> int:
    random.seed(time.time())
    return random.randint(1, L)

def create_packet(seq_id: int, length: int, is_useful: bool) -> bytes:
    random.seed(time.time())
    marker_bit = 1 if is_useful else 0
    marked_seq_id = (seq_id << 1) | marker_bit
    header = marked_seq_id.to_bytes(4, 'big') + length.to_bytes(4, 'big')
    payload = bytes([random.randint(0, 255) for _ in range(length)])
    return header + payload

def secret_producer(secret_queue: queue.Queue, symbols: List[int], buffer_size: int, t: float):
    random.seed(time.time())
    for symbol in symbols:
        secret_queue.put(('secret', symbol))
        time.sleep(random.uniform(t*0.8, t*2))
    for _ in range(buffer_size):
        secret_queue.put(('eof', None))

def sender_loop(args: argparse.Namespace):
    random.seed(time.time())
    print(f"Random seed initialized: {int(time.time())}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (args.host, args.port)
    
    message = load_secret_message(args)
    print(f"Loaded message: '{message}' (len={len(message)})")
    
    symbols = message_to_symbols(message, args.n, args.L)
    K = args.L // args.n
    alphabet = get_alphabet(K)
    print(f"Alphabet ({len(alphabet)} chars): {alphabet[:20]}{'...' if len(alphabet)>20 else ''}")
    print(f"Symbols: {symbols[:10]}{'...' if len(symbols)>10 else ''} (K={K})")
    
    secret_queue = queue.Queue(maxsize=args.buffer_size)
    
    producer_thread = threading.Thread(
        target=secret_producer, args=(secret_queue, symbols, args.buffer_size, args.t)
    )
    producer_thread.daemon = True
    producer_thread.start()
    
    seq_id_base = 0
    sent_secrets = 0
    start_time = time.time()
    
    print(f"Sending MARKER packets, n={args.n}, L={args.L}, buffer={args.buffer_size}")
    
    try:
        while time.time() - start_time < args.duration:
            is_useful = False
            length = dummy_length(args.L)
            
            try:
                msg_type, symbol = secret_queue.get_nowait()
                if msg_type == 'secret':
                    length = encode_symbol(symbol, args.n, args.L)
                    is_useful = True
                    sent_secrets += 1
                    print(f"MARKER=1 SECRET: sym={symbol} -> len={length} (sent={sent_secrets})")
                elif msg_type == 'eof':
                    pass
            except queue.Empty:
                pass
            
            if not is_useful:
                print(f"MARKER=0 DUMMY: len={length}")
            
            packet = create_packet(seq_id_base, length, is_useful)
            sock.sendto(packet, server_addr)
            
            seq_id_base += 1
            time.sleep(args.t)
            
    except KeyboardInterrupt:
        print("\nStopped")
    finally:
        sock.close()
        print(f"Total secrets sent: {sent_secrets}")

def main():
    args = parse_arguments()
    sender_loop(args)

if __name__ == "__main__":
    main()
