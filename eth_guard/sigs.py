"""Permit capability hints, never an inventory of unseen off-chain signatures."""
from .abi import call, words
from .transport import RpcError

# Probe discovered tokens plus well-known permit-style tokens on each chain.
MAJOR_TOKENS = {
    1: ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
        '0x6b175474e89094c44da98b954eedeac495271d0f'],
    8453: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'],
    42161: ['0xaf88d065e77c8cc2239327c5edb3a432268e5831'],
}

def inspect(rpc, tokens, owner, block):
    probes=[]
    for token in sorted(set(tokens)):
        try:
            nonce = words(call(rpc,token,'nonces(address)',[owner],block),1)[0]
            domain = call(rpc,token,'DOMAIN_SEPARATOR()',[],block)
            words(domain,1)
            probes.append({'token':token,'status':'permit_style_getters_present',
                           'nonce':nonce,'domain_separator':domain.lower()})
        except (RpcError,ValueError):
            probes.append({'token':token,'status':'unsupported_or_unavailable',
                           'nonce':None,'domain_separator':None})
    return {'open_signatures':'not_observable', 'tokens':probes,
            'note':'Unsubmitted ERC-2612, DAI-style and Permit2 signatures cannot be enumerated by RPC. Getter probes do not prove permit support. Executed permits are reflected in current allowances.'}
