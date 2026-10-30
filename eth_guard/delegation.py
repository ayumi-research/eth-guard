"""EIP-7702 current designation, with explicitly non-authoritative log hints."""
from .abi import address, log_key
from .transport import RpcError

def inspect(rpc, owner, block, logs):
    code_result = rpc.call('eth_getCode',[owner,block])
    if not isinstance(code_result, str):
        raise RpcError(f'eth_getCode returned {type(code_result).__name__}, expected hex string')
    code = code_result.lower()
    delegated = code.startswith('0xef0100') and len(code)==48
    target = address('0x'+code[8:]) if delegated else None
    relevant = sorted((log for log in logs if not log.get('removed') and
                       address(log['address']) == owner),key=log_key)
    def hint(log):
        return {'block_number':int(log['blockNumber'],16), 'transaction_hash':log['transactionHash']}
    return {'active':delegated, 'delegate':target,
            'code_kind':'delegated' if delegated else ('empty' if code=='0x' else 'contract_or_other'),
            'note':f'This EOA currently executes code written at {target} — verify you recognize it.'
                if delegated else 'No active EIP-7702 designation detected.',
            'first_activity_hint':hint(relevant[0]) if relevant else None,
            'last_activity_hint':hint(relevant[-1]) if relevant else None,
            'hint_caveat':'Account-emitted logs only; not delegation-change evidence. EIP-7702 emits no standard delegation event.'}
