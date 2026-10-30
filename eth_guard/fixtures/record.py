"""Manual network capture: python fixtures/record.py ADDRESS --rpc URL --output capture.json.

Records the exact read-only requests/results used by inspect (including RPC errors).
URLs are never stored. Inspect output before publishing; address activity is public.
The bundled offline fixture is synthetic, not falsely represented as a live capture.
"""
import argparse
import json
from eth_guard import HttpTransport, RpcError, inspect

class Recorder:
    def __init__(self,rpc): self.rpc,self.records=rpc,[]
    def call(self,method,params):
        record={'method':method,'params':params}
        try:
            record['result']=self.rpc.call(method,params)
        except RpcError:
            record['error']='Recorded RPC failure'
            raise
        finally:
            self.records.append(record)
        return record['result']

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('address')
    p.add_argument('--rpc',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--chain-id',type=int,default=1)
    p.add_argument('--from-block',type=int)
    p.add_argument('--lookback',type=int,default=50000)
    p.add_argument('--chunk-size',type=int,default=2000)
    args=p.parse_args(argv)
    rpc=Recorder(HttpTransport(args.rpc))
    complete = False
    try:
        inspect(args.address,rpc,chain_id=args.chain_id,from_block=args.from_block,
                lookback=args.lookback,chunk_size=args.chunk_size)
        complete = True
    finally:
        # Exclusive create prevents overwriting a capture by accident.
        with open(args.output,'x') as f:
            json.dump({'provenance':'live JSON-RPC capture','complete':complete,'records':rpc.records},f,indent=2)
            f.write('\n')

if __name__=='__main__': main()
