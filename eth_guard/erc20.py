"""Discover candidate pairs from Approval logs; trust current allowance calls."""
from .abi import address, call, words, topic, topic_address, human, log_key
from .transport import RpcError

APPROVAL = topic('Approval(address,address,uint256)')
MAX_UINT256 = (1 << 256)-1

def _sortable(log):
    try:
        return log_key(log)
    except (KeyError, TypeError, ValueError):
        return (1 << 256,)  # malformed entries sort last, then get warned by the parser

def metadata(rpc, token, owner, block, warnings):
    result = {'token': token, 'symbol': None, 'decimals': None,
              'balance_raw': None, 'balance_human': None}
    for name, sig, args in [('decimals','decimals()',[]), ('balance_raw','balanceOf(address)',[owner])]:
        try:
            value = words(call(rpc,token,sig,args,block),1)[0]
            if name == 'decimals' and value > 255: raise ValueError('Invalid decimals')
            result[name] = value
        except (RpcError, ValueError, TypeError, AttributeError, IndexError, KeyError):
            warnings.append(f'{token}: {name} unavailable')
    try:
        raw = bytes.fromhex(call(rpc,token,'symbol()',[],block)[2:])
        if len(raw) == 32:
            symbol = raw.rstrip(b'\0')
        else:
            if len(raw) < 64 or int.from_bytes(raw[:32],'big') != 32:
                raise ValueError('Invalid string offset')
            size = int.from_bytes(raw[32:64],'big')
            if size > 1024 or 64+size > len(raw): raise ValueError('Invalid string length')
            symbol = raw[64:64+size]
        result['symbol'] = symbol.decode('utf-8')
    except (RpcError, ValueError, TypeError, AttributeError, IndexError, UnicodeError):
        warnings.append(f'{token}: symbol unavailable')
    if result['balance_raw'] is not None:
        result['balance_human'] = human(result['balance_raw'], result['decimals'])
    return result

def discover(logs, owner, warnings):
    pairs = {}
    for log in sorted(logs,key=_sortable):
        try:
            ts = log['topics']
            # ERC721 uses the same signature but four indexed topics.
            if log.get('removed') or len(ts) != 3 or ts[0].lower() != APPROVAL: continue
            if topic_address(ts[1]) != owner: continue
            words(log['data'],1)
            pairs[(address(log['address']),topic_address(ts[2]))] = log
        except (ValueError, KeyError, TypeError):
            warnings.append('Skipped malformed ERC20 Approval log')
    return pairs

def inventory(rpc, pairs, owner, block, get_meta, timestamp, warnings):
    entries = []
    for (token, spender), log in sorted(pairs.items()):
        try:
            amount = words(call(rpc,token,'allowance(address,address)',[owner,spender],block),1)[0]
        except (RpcError, ValueError, TypeError, AttributeError, IndexError, KeyError):
            warnings.append(f'ERC20 allowance unavailable: {token}/{spender}')
            continue
        if not amount: continue
        meta = get_meta(token)
        entries.append(dict(channel='erc20', token=token, spender=spender,
            amount_raw=amount, amount_human=human(amount,meta['decimals']),
            symbol=meta['symbol'], decimals=meta['decimals'], unlimited=amount==MAX_UINT256,
            granted_at=timestamp(log['blockNumber']),
            grant_evidence='latest Approval observed in range; may not be original grant',
            transaction_hash=log['transactionHash'], expiration=None, nonce=None,
            active=True, spender_reputation='unknown'))
    return entries
