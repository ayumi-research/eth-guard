"""Read the public AllowanceTransfer mapping through its ABI getter."""
from .abi import address, topic, topic_address, words, call, human, log_key
from .transport import RpcError

ADDRESS = '0x000000000022d473030f116ddee9f6b43ac78ba3'
APPROVAL = topic('Approval(address,address,address,uint160,uint48)')
PERMIT = topic('Permit(address,address,address,uint160,uint48,uint48)')
MAX_UINT160 = (1 << 160)-1

def _sortable(log):
    try:
        return log_key(log)
    except (KeyError, TypeError, ValueError):
        return (1 << 256,)  # malformed entries sort last, then get warned by the parser

def discover(logs, owner, warnings):
    pairs = {}
    for log in sorted(logs,key=_sortable):
        try:
            ts = log['topics']
            if log.get('removed') or address(log['address']) != ADDRESS or len(ts)!=4: continue
            if ts[0].lower() not in (APPROVAL,PERMIT) or topic_address(ts[1])!=owner: continue
            words(log['data'],2 if ts[0].lower()==APPROVAL else 3)
            pairs[(topic_address(ts[2]),topic_address(ts[3]))] = log
        except (KeyError, ValueError, TypeError):
            warnings.append('Skipped malformed Permit2 log')
    return pairs

def inventory(rpc, pairs, owner, block, now, get_meta, timestamp, warnings):
    entries = []
    for (token,spender),log in sorted(pairs.items()):
        try:
            amount,expiration,nonce = words(call(rpc,ADDRESS,'allowance(address,address,address)',
                                               [owner,token,spender],block),3)
            if amount > MAX_UINT160 or expiration >= 1<<48 or nonce >= 1<<48:
                raise ValueError('Invalid packed allowance')
        except (RpcError,ValueError):
            warnings.append(f'Permit2 allowance unavailable: {token}/{spender}')
            continue
        if not amount: continue
        meta = get_meta(token)
        entries.append(dict(channel='permit2', token=token, spender=spender,
            amount_raw=amount, amount_human=human(amount,meta['decimals']),
            symbol=meta['symbol'], decimals=meta['decimals'], unlimited=amount==MAX_UINT160,
            granted_at=timestamp(log['blockNumber']),
            grant_evidence='latest Approval/Permit observed in range; may not be original grant',
            transaction_hash=log['transactionHash'], expiration=expiration, nonce=nonce,
            active=now<=expiration, spender_reputation='unknown'))
    return entries
