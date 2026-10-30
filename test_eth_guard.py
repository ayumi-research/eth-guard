"""Entirely offline: fixture replay and edge-case unit checks."""
import copy
import io
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch, Mock
from eth_guard import inspect, RpcError, HttpTransport
from eth_guard import erc20, permit2, delegation
from eth_guard.abi import keccak, selector, words, human, address
from eth_guard.cli import main
from eth_guard.report import risk_rank, OLD_SECONDS
from build_fixture import OWNER,TOKEN,SPENDER,OTHER,DELEGATE,NOW,encoded,Synthetic

FIXTURES=Path(__file__).parent/'eth_guard'/'fixtures'
class Replay:
    def __init__(self):
        self.records=json.loads((FIXTURES/'snapshot.json').read_text())['records']
        self.index=0
    def call(self,method,params):
        record=self.records[self.index]; self.index+=1
        assert (method,params)==(record['method'],record['params']), (method,params,record)
        if 'error' in record: raise RpcError(record['error'])
        return copy.deepcopy(record['result'])

class GuardTests(unittest.TestCase):
    def report(self): return inspect(OWNER,Replay(),from_block=80)
    def test_fixture_exact_report(self):
        rpc=Replay(); report=inspect(OWNER,rpc,from_block=80)
        self.assertEqual(report.to_dict(),json.loads((FIXTURES/'expected.json').read_text()))
        self.assertEqual(rpc.index,len(rpc.records))
    def test_keccak_vectors(self):
        self.assertEqual(keccak(b''),'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(selector('allowance(address,address)'),'0xdd62ed3e')
        self.assertEqual(selector('allowance(address,address,address)'),'0x927da105')
        self.assertEqual(erc20.APPROVAL,'0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925')
    def test_exact_large_human(self):
        self.assertEqual(human(1234567,6),'1.234567')
        self.assertEqual(human(10**77+1,18),str(10**59)+'.000000000000000001')
        self.assertEqual(human(0,18),'0')
        self.assertEqual(human(100,0),'100')
        self.assertIsNone(human(1,None))
    def test_validation(self):
        for value in ('0x123','x'*42,None,'0x'+'z'*40):
            with self.assertRaises(ValueError): address(value)
        with self.assertRaises(ValueError): words('0x01',1)
    def test_current_state_not_event_amount(self):
        entry=next(e for e in self.report().entries if e['channel']=='erc20' and e['spender']==SPENDER)
        self.assertEqual(entry['amount_raw'],erc20.MAX_UINT256)
        self.assertEqual(entry['risk_rank'],'HIGH')
    def test_revoked_and_nft_excluded(self):
        entries=self.report().entries
        self.assertEqual(len(entries),4)
        self.assertTrue(all(e['token']==TOKEN for e in entries))
        self.assertEqual(sum(e['channel']=='erc20' for e in entries),2)
    def test_expired_permit2(self):
        entry=next(e for e in self.report().entries if e['channel']=='permit2' and e['spender']==SPENDER)
        self.assertFalse(entry['active']); self.assertEqual(entry['risk_rank'],'LOW')
        self.assertEqual(entry['nonce'],7)
    def test_delegation(self):
        d=self.report().delegation
        self.assertTrue(d['active']); self.assertEqual(d['delegate'],DELEGATE)
        self.assertIn('not delegation-change',d['hint_caveat'])
        self.assertEqual(d['first_activity_hint']['block_number'],95)
    def test_nondelegated_code(self):
        for code,kind in [('0x','empty'),('0x6000','contract_or_other'),('0xef010001','contract_or_other')]:
            d=delegation.inspect(Mock(call=Mock(return_value=code)),OWNER,'0x64',[])
            self.assertFalse(d['active']); self.assertEqual(d['code_kind'],kind)
    def test_signatures_explicitly_unobservable(self):
        s=self.report().signatures
        self.assertEqual(s['open_signatures'],'not_observable')
        self.assertEqual(next(t for t in s['tokens'] if t['token']==TOKEN)['nonce'],4)
    def test_balances(self):
        token=self.report().tokens[0]
        self.assertEqual(token['balance_human'],'2.5'); self.assertEqual(token['symbol'],'TEST')
    def test_risk_boundaries(self):
        e=dict(active=True,amount_raw=1,unlimited=False,spender_reputation='unknown',granted_at=NOW-OLD_SECONDS)
        self.assertEqual(risk_rank(e,NOW)[0],'LOW')
        e['granted_at']+=1
        self.assertEqual(risk_rank(e,NOW)[0],'MED')
        e['granted_at']=None
        self.assertEqual(risk_rank(e,NOW)[0],'MED')
        e['unlimited']=True
        self.assertEqual(risk_rank(e,NOW)[0],'HIGH')
    def test_chain_mismatch(self):
        with self.assertRaises(ValueError): inspect(OWNER,Replay(),chain_id=8453)
    def test_invalid_range(self):
        with self.assertRaises(ValueError): inspect(OWNER,Replay(),from_block=101)
        with self.assertRaises(ValueError): inspect(OWNER,Replay(),chunk_size=0)
    def test_chunked_discovery(self):
        a=inspect(OWNER,Synthetic(),from_block=80,chunk_size=5)
        self.assertEqual(a.to_json(),self.report().to_json())
    def test_discovery_errors_abort(self):
        rpc=Replay(); rpc.records[2].pop('result'); rpc.records[2]['error']='range failed'
        with self.assertRaises(RpcError): inspect(OWNER,rpc,from_block=80)
    def test_reorg_aborts(self):
        rpc=Replay(); rpc.records[-1]['result']['hash']='0xdead'
        with self.assertRaises(RpcError): inspect(OWNER,rpc,from_block=80)
    def test_metadata_failure_explicit(self):
        rpc=Replay()
        for r in rpc.records:
            if r['method']=='eth_call' and r['params'][0]['data']==selector('decimals()'):
                r.pop('result'); r['error']='revert'
        report=inspect(OWNER,rpc,from_block=80)
        self.assertIsNone(report.entries[0]['amount_human'])
        self.assertTrue(any('decimals unavailable' in w for w in report.warnings))
    def test_allowance_failure_explicit(self):
        class Fail(Synthetic):
            def call(self,method,params):
                if method=='eth_call' and params[0]['data'].startswith('0xdd62ed3e'): raise RpcError('revert')
                return super().call(method,params)
        report=inspect(OWNER,Fail(),from_block=80)
        self.assertEqual(len(report.entries),2)
        self.assertTrue(any('allowance unavailable' in w for w in report.warnings))
    def test_deterministic_output(self): self.assertEqual(self.report().to_json(),self.report().to_json())
    def test_markdown_coverage(self):
        md=self.report().to_markdown()
        for term in ('HIGH','EIP-7702','not a complete lifetime','Unsubmitted','Raw amount'): self.assertIn(term,md)
    def test_cli_json(self):
        with patch('eth_guard.cli.HttpTransport',return_value=Replay()), patch('sys.stdout',new_callable=io.StringIO) as out:
            self.assertEqual(main(['inspect',OWNER,'--rpc','https://example.invalid','--from-block','80','--json']),0)
            self.assertEqual(json.loads(out.getvalue())['address'],OWNER)
    def test_cli_error(self):
        with patch('sys.stderr',new_callable=io.StringIO):
            self.assertEqual(main(['inspect','bad','--rpc','https://example.invalid']),1)
    def test_read_only_boundary(self):
        rpc=HttpTransport('https://example.invalid')
        for method in ('eth_sendRawTransaction','eth_sendTransaction','personal_sign','eth_sign','debug_traceCall'):
            with self.assertRaises(ValueError): rpc.call(method,[])
    def test_http_errors(self):
        rpc=HttpTransport('https://example.invalid')
        response=Mock(); response.json.return_value={'jsonrpc':'2.0','id':1,'error':{'code':-32000}}
        with patch.object(rpc.session,'post',return_value=response):
            with self.assertRaises(RpcError): rpc.call('eth_chainId',[])
    def test_http_success_and_timeout(self):
        rpc=HttpTransport('https://example.invalid',timeout=5)
        response=Mock(); response.json.return_value={'jsonrpc':'2.0','id':1,'result':'0x1'}
        with patch.object(rpc.session,'post',return_value=response) as post:
            self.assertEqual(rpc.call('eth_chainId',[]),'0x1')
            self.assertEqual(post.call_args.kwargs['timeout'],5)
    def test_http_mismatched_id(self):
        rpc=HttpTransport('https://example.invalid')
        response=Mock(); response.json.return_value={'jsonrpc':'2.0','id':99,'result':'0x1'}
        with patch.object(rpc.session,'post',return_value=response):
            with self.assertRaises(RpcError): rpc.call('eth_chainId',[])

    def test_recorder_success_is_explicit(self):
        from eth_guard.fixtures.record import main as record
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'capture.json'
            with patch('eth_guard.fixtures.record.HttpTransport', return_value=Synthetic()):
                record([OWNER, '--rpc', 'https://example.invalid', '--output', str(dest)])
            capture = json.loads(dest.read_text())
            self.assertTrue(capture['complete'])
            self.assertTrue(capture['records'])
            self.assertNotIn('example.invalid', dest.read_text())

    def test_recorder_failure_is_explicit_and_sanitized(self):
        from eth_guard.fixtures.record import main as record
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'capture.json'
            rpc = Mock(call=Mock(side_effect=RpcError('sensitive provider context')))
            with patch('eth_guard.fixtures.record.HttpTransport', return_value=rpc):
                with self.assertRaises(RpcError):
                    record([OWNER, '--rpc', 'https://example.invalid', '--output', str(dest)])
            capture = json.loads(dest.read_text())
            self.assertFalse(capture['complete'])
            self.assertEqual(capture['records'][0]['error'], 'Recorded RPC failure')
            self.assertNotIn('sensitive provider context', dest.read_text())

    def test_recorder_preserves_existing_capture(self):
        from eth_guard.fixtures.record import main as record
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'capture.json'
            dest.write_text('existing capture')
            with patch('eth_guard.fixtures.record.HttpTransport', return_value=Synthetic()):
                with self.assertRaises(FileExistsError):
                    record([OWNER, '--rpc', 'https://example.invalid', '--output', str(dest)])
            self.assertEqual(dest.read_text(), 'existing capture')

    def test_symbol_injection_neutralized(self):
        # Adversarial bytes32 symbol with ESC + markdown link must not survive to markdown.
        evil = '\x1b[2J[' + OWNER + '](https://example.invalid)'
        rpc = Replay()
        base = inspect(OWNER, rpc, from_block=80)
        md = base.to_markdown()
        class Injected(Replay):
            pass
        # Rebuild the report with the hostile symbol patched into metadata output.
        import eth_guard.erc20 as e
        original = e.metadata
        def patched(rpc_arg, token, owner_arg, block, warnings):
            meta = original(rpc_arg, token, owner_arg, block, warnings)
            if meta['symbol'] is not None:
                meta['symbol'] = evil
            return meta
        with patch.object(e, 'metadata', patched):
            dirty = inspect(OWNER, Replay(), from_block=80)
        text = dirty.to_markdown()
        self.assertNotIn('\x1b', text)
        # brackets are backslash-escaped, so the link renders as literal text, not a link
        self.assertIn('\\[' + OWNER + '\\](https://example.invalid)', text)

    def test_null_provider_results_warn_not_crash(self):
        from build_fixture import Synthetic
        class Nulling(Synthetic):
            def call(self, method, params):
                if method == 'eth_call':
                    return None  # provider returns null for every contract call
                return super().call(method, params)
        rpc = Nulling()
        report = inspect(OWNER, rpc, from_block=80, chunk_size=50000)
        self.assertTrue(any('unavailable' in w for w in report.warnings),
                        f'expected metadata warnings, got {report.warnings}')

    def test_null_block_body_is_controlled_error(self):
        class BadHead(Replay):
            def call(self, method, params):
                if method == 'eth_getBlockByNumber':
                    return None
                return super().call(method, params)
        with self.assertRaises(RpcError):
            inspect(OWNER, BadHead(), from_block=80)

if __name__=='__main__': unittest.main()
