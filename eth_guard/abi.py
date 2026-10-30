"""Minimal Ethereum ABI and Keccak-256 (Ethereum uses Keccak, not SHA3)."""
import re

_MASK = (1 << 64) - 1
_RC = (0x1,0x8082,0x800000000000808a,0x8000000080008000,0x808b,0x80000001,
       0x8000000080008081,0x8000000000008009,0x8a,0x88,0x80008009,0x8000000a,
       0x8000808b,0x800000000000008b,0x8000000000008089,0x8000000000008003,
       0x8000000000008002,0x8000000000000080,0x800a,0x800000008000000a,
       0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008)
_ROT = ((0,36,3,41,18),(1,44,10,45,2),(62,6,43,15,61),
        (28,55,25,21,56),(27,20,39,8,14))

def keccak(data: bytes) -> str:
    data = bytearray(data)
    pad = 136 - len(data) % 136
    data.extend(b'\x81' if pad == 1 else b'\x01' + b'\0' * (pad-2) + b'\x80')
    a = [0]*25
    def rol(v, n): return ((v << n) | (v >> (64-n))) & _MASK
    for start in range(0, len(data), 136):
        for i in range(17):
            a[i] ^= int.from_bytes(data[start+8*i:start+8*i+8], 'little')
        for rc in _RC:
            c = [a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
            d = [c[(x-1)%5]^rol(c[(x+1)%5],1) for x in range(5)]
            b = [0]*25
            for x in range(5):
                for y in range(5):
                    b[y+5*((2*x+3*y)%5)] = rol(a[x+5*y]^d[x], _ROT[x][y])
            for x in range(5):
                for y in range(5):
                    a[x+5*y] = b[x+5*y]^((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
            a[0] ^= rc
    return b''.join(v.to_bytes(8,'little') for v in a)[:32].hex()

def topic(signature): return '0x'+keccak(signature.encode())
def selector(signature): return topic(signature)[:10]

def address(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', value):
        raise ValueError('Expected a 20-byte 0x Ethereum address')
    return value.lower()

def word(value): return address(value)[2:].rjust(64,'0')
def topic_address(value):
    if len(value) != 66 or value[2:26] != '0'*24:
        raise ValueError('Invalid indexed address')
    return address('0x'+value[-40:])

def words(data, count):
    if not isinstance(data, str) or not re.fullmatch(r'0x[0-9a-fA-F]*', data) or len(data) != 2+64*count:
        raise ValueError('Invalid ABI word response')
    return [int(data[2+i*64:2+(i+1)*64],16) for i in range(count)]

def call(rpc, target, signature, args, block):
    return rpc.call('eth_call', [{'to': address(target), 'data': selector(signature)+''.join(word(a) for a in args)}, block])

def human(raw, decimals):
    if decimals is None: return None
    if decimals == 0: return str(raw)
    s = str(raw).zfill(decimals+1)
    return (s[:-decimals]+'.'+s[-decimals:]).rstrip('0').rstrip('.')

def log_key(log):
    return (int(log['blockNumber'],16), int(log['transactionIndex'],16), int(log['logIndex'],16))
