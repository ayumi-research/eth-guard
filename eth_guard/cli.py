import argparse
import sys
from . import inspect, HttpTransport, RpcError
from .report import CHAINS

def main(argv=None):
    parser=argparse.ArgumentParser(description='Read-only, range-limited Ethereum allowance and delegation inventory')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('inspect')
    p.add_argument('address')
    p.add_argument('--rpc',required=True)
    p.add_argument('--chain-id',type=int,choices=CHAINS,default=1)
    p.add_argument('--from-block',type=int)
    p.add_argument('--lookback',type=int,default=50000)
    p.add_argument('--chunk-size',type=int,default=2000)
    fmt=p.add_mutually_exclusive_group()
    fmt.add_argument('--json',action='store_true')
    fmt.add_argument('--md',action='store_true')
    args=parser.parse_args(argv)
    try:
        report=inspect(args.address,HttpTransport(args.rpc),chain_id=args.chain_id,
                       from_block=args.from_block,lookback=args.lookback,chunk_size=args.chunk_size)
    except (RpcError,ValueError,KeyError,TypeError) as exc:
        print(f'eth-guard: {exc}',file=sys.stderr)
        return 1
    print(report.to_json() if args.json else report.to_markdown(),end='')
    return 0
