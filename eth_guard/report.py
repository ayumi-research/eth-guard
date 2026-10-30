"""Snapshot orchestration and transparent risk rules."""
from dataclasses import dataclass, asdict
import json
import re
from . import erc20, permit2, delegation, sigs
from .abi import address, word, hex_int
from .transport import RpcError

CHAINS = {1:'mainnet',8453:'base',42161:'arbitrum'}
OLD_SECONDS = 180*86400
LIMITATIONS = [
    'Discovery is limited to logs in the fetched range; this is not a complete lifetime inventory.',
    'Nonstandard tokens and silent allowance changes may be missed. NFT approvals are excluded.',
    'Unsubmitted signatures and delegation-change history are not observable in this report.',
    'Grant times are the latest matching events in range, not proven original authorization times.',
    'Spender reputation is unknown; LOW does not mean safe.',
]

def risk_rank(entry, now):
    if not entry['active'] or entry['amount_raw']==0:
        return 'LOW','Expired or zero allowance'
    if entry['unlimited'] and entry['spender_reputation']=='unknown':
        return 'HIGH','Unlimited allowance to an unknown spender'
    if not entry['unlimited'] and entry['granted_at'] is not None and now-entry['granted_at']>=OLD_SECONDS:
        return 'LOW','Capped allowance with an observed grant at least 180 days old'
    return 'MED','Active allowance without a HIGH or LOW rule match'

@dataclass
class Report:
    address: str
    chain_id: int
    chain: str
    block_number: int
    block_hash: str
    timestamp: int
    from_block: int
    entries: list
    tokens: list
    delegation: dict
    signatures: dict
    warnings: list
    limitations: list

    def to_dict(self): return asdict(self)
    def to_json(self): return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)+'\n'
    def to_markdown(self):
        def escape(value):
            text = ''.join(ch if ch.isprintable() else ' ' for ch in str(value))
            # Escape provider backslashes before introducing any Markdown escapes.
            text = text.replace('\\', '\\\\')
            for punctuation in '`*_{}[]()#+-.!~>|':
                text = text.replace(punctuation, '\\'+punctuation)
            # Entities keep HTML and table delimiters literal without an extra slash.
            return (text.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
                        .replace('\\&gt;', '&gt;').replace('\\|','&#124;'))
        lines = ['# eth-guard',f'Address: `{self.address}`',
                 f'Chain: {self.chain} ({self.chain_id}); snapshot block {self.block_number} (`{self.block_hash}`).',
                 f'Log range: {self.from_block}–{self.block_number}. Snapshot timestamp: {self.timestamp}.',
                 '', '## EIP-7702',self.delegation['note'],self.delegation['hint_caveat']]
        for name in ('first_activity_hint','last_activity_hint'):
            if self.delegation[name]: lines.append(f'{name}: {self.delegation[name]}')
        lines += ['', '## Allowances', '',
                  '| Risk | Channel | Token | Spender | Raw amount | Human amount | Granted at (Unix) | Expiration | Active | Reason |',
                  '|---|---|---|---|---|---|---|---|---|---|']
        for e in self.entries:
            fields = [e['risk_rank'],e['channel'],e['token'],e['spender'],e['amount_raw'],
                      e['amount_human'] if e['amount_human'] is not None else 'unknown',
                      e['granted_at'],e['expiration'],e['active'],e['risk_reason']]
            lines.append('| '+' | '.join(escape(f) for f in fields)+' |')
        if not self.entries: lines.append('\nNo nonzero allowances found among discovered pairs; this is not proof of no approvals.')
        lines += ['', '## Token balances', '']
        for token in self.tokens:
            lines.append(f"- {token['token']} ({escape(token['symbol'])}): {token['balance_raw']} raw; {token['balance_human']} human; decimals {token['decimals']}")
        lines += ['', '## Permit signatures',self.signatures['note']]
        for token in self.signatures['tokens']:
            lines.append(f"- {token['token']}: {token['status']}; nonce {token['nonce']}")
        lines += ['', '## Coverage and warnings', '']
        lines.extend('- '+escape(w) for w in self.limitations+self.warnings)
        return '\n'.join(lines)+'\n'

def _snapshot_block(result):
    try:
        if not isinstance(result, dict): raise ValueError('Expected a block object')
        number, timestamp = hex_int(result['number']), hex_int(result['timestamp'])
        block_hash = result['hash']
        if not isinstance(block_hash, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', block_hash):
            raise ValueError('Expected a block hash')
        return number, timestamp, block_hash.lower()
    except (KeyError, TypeError, ValueError) as exc:
        raise RpcError('eth_getBlockByNumber returned malformed snapshot block') from exc

def inspect(owner, rpc, *, chain_id=1, from_block=None, lookback=50000, chunk_size=2000):
    owner = address(owner)
    if chain_id not in CHAINS: raise ValueError('Unsupported chain ID')
    if lookback<=0 or chunk_size<=0: raise ValueError('lookback and chunk_size must be positive')
    actual = rpc.call('eth_chainId',[])
    try:
        actual = hex_int(actual)
    except ValueError as exc:
        raise RpcError('eth_chainId returned malformed hex integer') from exc
    if actual != chain_id: raise ValueError(f'RPC chain {actual} does not match requested chain {chain_id}')
    head = rpc.call('eth_getBlockByNumber',['latest',False])
    end, now, block_hash = _snapshot_block(head)
    start = max(0,end-lookback+1) if from_block is None else from_block
    if start<0 or start>end: raise ValueError('from_block must be between zero and snapshot block')
    block = hex(end)
    warnings=[]
    def logs(extra):
        found=[]
        for lo in range(start,end+1,chunk_size):
            result = rpc.call('eth_getLogs',[dict(fromBlock=hex(lo),toBlock=hex(min(end,lo+chunk_size-1)),**extra)])
            if not isinstance(result, list):
                raise RpcError('eth_getLogs returned a non-list result')
            found.extend(result)
        return found
    # Discovery failures abort: never silently turn an RPC range failure into an empty inventory.
    approvals = logs({'topics':[erc20.APPROVAL,'0x'+word(owner)]})
    permits = logs({'address':permit2.ADDRESS,'topics':[[permit2.APPROVAL,permit2.PERMIT],'0x'+word(owner)]})
    activity = logs({'address':owner})
    epairs = erc20.discover(approvals,owner,warnings)
    ppairs = permit2.discover(permits,owner,warnings)
    cache={}
    times={block:now}
    def timestamp(number):
        if number not in times:
            try:
                times[number]=int(rpc.call('eth_getBlockByNumber',[number,False])['timestamp'],16)
            except (RpcError,ValueError,TypeError,KeyError):
                times[number]=None
                warnings.append(f'Grant timestamp unavailable at block {number}')
        return times[number]
    def get_meta(token):
        if token not in cache: cache[token]=erc20.metadata(rpc,token,owner,block,warnings)
        return cache[token]
    entries = erc20.inventory(rpc,epairs,owner,block,get_meta,timestamp,warnings)
    entries += permit2.inventory(rpc,ppairs,owner,block,now,get_meta,timestamp,warnings)
    for entry in entries:
        entry['risk_rank'],entry['risk_reason'] = risk_rank(entry,now)
    entries.sort(key=lambda e:({'HIGH':0,'MED':1,'LOW':2}[e['risk_rank']],e['token'],e['spender'],e['channel']))
    delegated = delegation.inspect(rpc,owner,block,activity,warnings)
    signatures = sigs.inspect(rpc,set(t for t,s in epairs)|set(t for t,s in ppairs)|set(sigs.MAJOR_TOKENS[chain_id]),owner,block)
    # Numeric block tags are widely supported. Detect a reorg during collection.
    check = rpc.call('eth_getBlockByNumber',[block,False])
    if _snapshot_block(check)!=(end,now,block_hash): raise RpcError('Snapshot reorganized during inspection; retry')
    return Report(owner,chain_id,CHAINS[chain_id],end,block_hash,now,start,entries,
                  [cache[t] for t in sorted(cache)],delegated,signatures,sorted(set(warnings)),list(LIMITATIONS))
