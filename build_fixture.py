"""Rebuild deterministic synthetic RPC fixtures; no network."""
import json
from pathlib import Path
from eth_guard import inspect, RpcError
from eth_guard.abi import word, selector
from eth_guard import erc20, permit2

OWNER='0x'+'11'*20
TOKEN='0x'+'22'*20
SPENDER='0x'+'33'*20
OTHER='0x'+'44'*20
ZERO='0x'+'55'*20
DELEGATE='0x'+'66'*20
NFT='0x'+'77'*20
NOW=1800000000

def encoded(*values): return '0x'+''.join(f'{v:064x}' for v in values)
def event(contract,topics,data,block=90,index=0):
    return dict(address=contract,topics=topics,data=data,blockNumber=hex(block),
                transactionIndex='0x0',logIndex=hex(index),transactionHash='0x'+f'{index+1:064x}',removed=False)

class Synthetic:
    def __init__(self): self.records=[]
    def call(self,method,params):
        rec=dict(method=method,params=params)
        self.records.append(rec)
        if method=='eth_chainId': result='0x1'
        elif method=='eth_getBlockByNumber':
            n=100 if params[0]=='latest' else int(params[0],16)
            result=dict(number=hex(n),timestamp=hex(NOW if n==100 else NOW-200*86400),hash='0x'+f'{n:064x}')
        elif method=='eth_getCode': result='0xef0100'+DELEGATE[2:]
        elif method=='eth_getLogs':
            f=params[0]
            if f.get('address')==OWNER:
                result=[event(OWNER,[], '0x',95,9)]
            elif f.get('address')==permit2.ADDRESS:
                result=[event(permit2.ADDRESS,[permit2.APPROVAL,'0x'+word(OWNER),'0x'+word(TOKEN),'0x'+word(SPENDER)],encoded(permit2.MAX_UINT160,NOW-1),90,5),
                        event(permit2.ADDRESS,[permit2.PERMIT,'0x'+word(OWNER),'0x'+word(TOKEN),'0x'+word(OTHER)],encoded(100,NOW+100,1),90,6)]
            else:
                result=[event(TOKEN,[erc20.APPROVAL,'0x'+word(OWNER),'0x'+word(s)],encoded(a),90,i)
                        for i,(s,a) in enumerate([(SPENDER,1),(OTHER,2),(ZERO,100)])]
                result.append(event(NFT,[erc20.APPROVAL,'0x'+word(OWNER),'0x'+word(SPENDER),encoded(1)],'0x',90,4))
            result=[l for l in result if int(f['fromBlock'],16)<=int(l['blockNumber'],16)<=int(f['toBlock'],16)]
        elif method=='eth_call':
            req=params[0]; data=req['data']; sel=data[:10]; target=req['to']
            if sel==selector('allowance(address,address)'):
                spender='0x'+data[-40:]
                result=encoded({SPENDER:erc20.MAX_UINT256,OTHER:1234567,ZERO:0}[spender])
            elif sel==selector('allowance(address,address,address)'):
                result=encoded(permit2.MAX_UINT160,NOW-1,7) if data.endswith(word(SPENDER)) else encoded(100,NOW+100,1)
            elif target!=TOKEN:
                rec['error']='Unsupported synthetic token'
                raise RpcError(rec['error'])
            elif sel==selector('decimals()'): result=encoded(6)
            elif sel==selector('balanceOf(address)'): result=encoded(2500000)
            elif sel==selector('symbol()'): result='0x'+b'TEST'.ljust(32,b'\0').hex()
            elif sel==selector('nonces(address)'): result=encoded(4)
            elif sel==selector('DOMAIN_SEPARATOR()'): result=encoded(123)
            else: raise AssertionError((method,params))
        else: raise AssertionError(method)
        rec['result']=result
        return result

if __name__=='__main__':
    rpc=Synthetic()
    report=inspect(OWNER,rpc,from_block=80)
    dest=Path(__file__).parent/'eth_guard'/'fixtures'
    (dest/'snapshot.json').write_text(json.dumps({'provenance':'synthetic ABI-shaped RPC responses; no live capture claimed','records':rpc.records},indent=2)+'\n')
    (dest/'expected.json').write_text(report.to_json())
