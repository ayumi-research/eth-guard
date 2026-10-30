"""Offline regressions for the v0.1.1 re-gate findings."""
import copy
from html.parser import HTMLParser
from unittest.mock import Mock, patch

import pytest
import requests
from markdown_it import MarkdownIt

from build_fixture import OWNER, TOKEN, OTHER, NOW, Synthetic, event, encoded
from eth_guard import HttpTransport, RpcError, inspect
from eth_guard import erc20, permit2
from eth_guard.abi import selector, word
from eth_guard.cli import main


class RenderedText(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.text = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)

    def handle_data(self, data):
        self.text.append(data)


@pytest.mark.parametrize(('symbol', 'escaped'), [
    (r'\[ok\](https://e.invalid)', r'\\\[ok\\\]\(https://e\.invalid\)'),
    ('**TRUSTED**', r'\*\*TRUSTED\*\*'),
    ('`TRUSTED`', r'\`TRUSTED\`'),
    ('![ok](https://e.invalid)', r'\!\[ok\]\(https://e\.invalid\)'),
    ('_*{}[]()#+-.!~', r'\_\*\{\}\[\]\(\)\#\+\-\.\!\~'),
    ('<b>&>|', '&lt;b&gt;&amp;&gt;&#124;'),
    (r'\>\|', r'\\&gt;\\&#124;'),
    ('\x1b\x00\r\n\u202eTEST', '     TEST'),
])
def test_provider_symbol_renders_as_literal_text(symbol, escaped):
    class Symbol(Synthetic):
        def call(self, method, params):
            if method == 'eth_call' and params[0]['data'] == selector('symbol()'):
                return '0x' + symbol.encode().ljust(32, b'\0').hex()
            return super().call(method, params)

    report = inspect(OWNER, Symbol(), from_block=80)
    assert report.tokens[0]['symbol'] == symbol
    markdown = report.to_markdown()
    assert escaped in markdown
    assert '](http' not in markdown
    # Render the complete token-balance section, where symbols are displayed.
    section = markdown.split('## Token balances\n', 1)[1].split('## Permit signatures', 1)[0]
    rendered = RenderedText(MarkdownIt('commonmark').render(section))
    literal = ''.join(ch if ch.isprintable() else ' ' for ch in symbol)
    assert f'({literal}):' in ''.join(rendered.text)
    assert not {'a', 'img', 'strong', 'em', 'code', 'b'} & set(rendered.tags)


def test_markdown_table_delimiters_stay_in_their_cell():
    report = inspect(OWNER, Synthetic(), from_block=80)
    report.entries[0]['risk_reason'] = r'left\|right **bold** <script>'
    markdown = report.to_markdown()
    assert r'left\\&#124;right \*\*bold\*\* &lt;script&gt;' in markdown
    section = markdown.split('## Allowances\n', 1)[1].split('## Token balances', 1)[0]
    rendered = RenderedText(MarkdownIt('commonmark').enable('table').render(section))
    assert rendered.tags.count('td') == len(report.entries) * 10
    assert report.entries[0]['risk_reason'] in ''.join(rendered.text)
    assert not {'strong', 'script'} & set(rendered.tags)


@pytest.mark.parametrize('bad', [None, {}, '', 'not logs', 42, True])
@pytest.mark.parametrize('collection', ['erc20', 'permit2', 'activity'])
def test_wrong_discovery_collection_aborts(bad, collection):
    class BadLogs(Synthetic):
        def call(self, method, params):
            if method == 'eth_getLogs':
                target = params[0].get('address')
                kind = 'activity' if target == OWNER else 'permit2' if target == permit2.ADDRESS else 'erc20'
                if kind == collection:
                    return bad
            return super().call(method, params)

    with pytest.raises(RpcError, match='eth_getLogs'):
        inspect(OWNER, BadLogs(), from_block=80, chunk_size=5)


def test_bad_later_discovery_chunk_aborts_after_valid_chunk():
    class BadLaterChunk(Synthetic):
        def call(self, method, params):
            if method == 'eth_getLogs' and params[0]['fromBlock'] == '0x64':
                return {}
            return super().call(method, params)

    with pytest.raises(RpcError, match='eth_getLogs'):
        inspect(OWNER, BadLaterChunk(), from_block=80, chunk_size=20)


def approval(channel, block, index=0):
    topics = ['0x' + word(OWNER), '0x' + word(TOKEN), '0x' + word(OTHER)]
    if channel == 'erc20':
        return event(TOKEN, [erc20.APPROVAL, topics[0], topics[2]], encoded(2), block, index)
    return event(permit2.ADDRESS, [permit2.PERMIT, *topics], encoded(100, NOW+100, 1), block, index)


@pytest.mark.parametrize('channel', ['erc20', 'permit2'])
@pytest.mark.parametrize('reverse', [False, True])
def test_malformed_old_event_never_overwrites_valid_recent_risk(channel, reverse):
    old, recent = approval(channel, 85), approval(channel, 100, 1)
    old['transactionIndex'] = None
    events = [old, recent]
    if reverse:
        events.reverse()

    class Ordering(Synthetic):
        def call(self, method, params):
            if method == 'eth_getLogs':
                target = params[0].get('address')
                if (channel == 'erc20' and target is None) or (channel == 'permit2' and target == permit2.ADDRESS):
                    return copy.deepcopy(events)
            return super().call(method, params)

    report = inspect(OWNER, Ordering(), from_block=80)
    entry = next(e for e in report.entries if e['channel'] == channel and e['spender'] == OTHER)
    assert entry['token'] == TOKEN
    assert 0 < entry['amount_raw'] < (erc20.MAX_UINT256 if channel == 'erc20' else permit2.MAX_UINT160)
    assert entry['granted_at'] == NOW == 1800000000
    assert entry['risk_rank'] == 'MED'
    assert entry['transaction_hash'] == recent['transactionHash']
    assert any('Skipped malformed ' + ('ERC20 Approval' if channel == 'erc20' else 'Permit2') in w for w in report.warnings)


BAD_FIELDS = [
    ('topics', None), ('topics', {}), ('topics', ''), ('topics', [None]),
    ('topics', [None, None, None, None]), ('topics', [42]),
    ('transactionHash', None), ('transactionHash', 42),
    *[(field, value) for field in ('blockNumber', 'transactionIndex', 'logIndex')
      for value in (None, {}, 42, True, 'garbage', '-0x1', '1', '0x')],
    ('address', None), ('address', {}),
]


@pytest.mark.parametrize('channel', ['erc20', 'permit2'])
@pytest.mark.parametrize(('field', 'bad'), BAD_FIELDS)
def test_malformed_approval_fields_warn_and_preserve_valid_pair(channel, field, bad):
    valid, malformed = approval(channel, 100), approval(channel, 85)
    malformed[field] = bad
    warnings = []
    module = erc20 if channel == 'erc20' else permit2
    pairs = module.discover([valid, malformed], OWNER, warnings)
    assert pairs == {(TOKEN, OTHER): valid}
    assert len(warnings) == 1
    assert 'Skipped malformed' in warnings[0]


@pytest.mark.parametrize('channel', ['erc20', 'permit2'])
@pytest.mark.parametrize('field', ['topics', 'transactionHash', 'blockNumber', 'transactionIndex', 'logIndex', 'address', 'data'])
def test_missing_approval_fields_warn(channel, field):
    malformed = approval(channel, 85)
    del malformed[field]
    warnings = []
    module = erc20 if channel == 'erc20' else permit2
    assert module.discover([malformed], OWNER, warnings) == {}
    assert len(warnings) == 1


@pytest.mark.parametrize('channel', ['erc20', 'permit2'])
@pytest.mark.parametrize('bad', [None, [], '', 42])
def test_nonobject_approval_warns(channel, bad):
    warnings = []
    module = erc20 if channel == 'erc20' else permit2
    assert module.discover([bad], OWNER, warnings) == {}
    assert len(warnings) == 1


@pytest.mark.parametrize('channel', ['erc20', 'permit2'])
@pytest.mark.parametrize('field', ['blockNumber', 'transactionIndex', 'logIndex'])
def test_valid_ordering_uses_numeric_keys(channel, field):
    old, recent = approval(channel, 85), approval(channel, 85)
    old[field], recent[field] = '0x9', '0x10'
    warnings = []
    module = erc20 if channel == 'erc20' else permit2
    assert module.discover([recent, old], OWNER, warnings) == {(TOKEN, OTHER): recent}
    assert warnings == []


@pytest.mark.parametrize(('field', 'bad'), BAD_FIELDS)
def test_malformed_activity_fields_warn_and_keep_valid_hints(field, bad):
    malformed = event(OWNER, [], '0x', 85)
    malformed[field] = bad
    assert_activity_warning(malformed)


@pytest.mark.parametrize('field', ['topics', 'transactionHash', 'blockNumber', 'transactionIndex', 'logIndex', 'address'])
def test_missing_activity_fields_warn(field):
    malformed = event(OWNER, [], '0x', 85)
    del malformed[field]
    assert_activity_warning(malformed)


@pytest.mark.parametrize('bad', [None, [], '', 42])
def test_nonobject_activity_warns(bad):
    assert_activity_warning(bad)


def test_all_malformed_activity_has_no_hints_and_warns():
    class Activity(Synthetic):
        def call(self, method, params):
            if method == 'eth_getLogs' and params[0].get('address') == OWNER:
                return [None, {}]
            return super().call(method, params)

    report = inspect(OWNER, Activity(), from_block=80)
    assert len(report.entries) == 4
    assert report.delegation['first_activity_hint'] is None
    assert report.delegation['last_activity_hint'] is None
    assert 'Skipped malformed account activity log' in report.warnings


def assert_activity_warning(malformed):
    class Activity(Synthetic):
        def call(self, method, params):
            result = super().call(method, params)
            if method == 'eth_getLogs' and params[0].get('address') == OWNER:
                return [malformed, *result]
            return result

    report = inspect(OWNER, Activity(), from_block=80)
    assert len(report.entries) == 4
    assert report.delegation['first_activity_hint']['block_number'] == 95
    assert report.delegation['last_activity_hint']['block_number'] == 95
    assert 'Skipped malformed account activity log' in report.warnings


BAD_BLOCKS = [None, {}, [], '', 42]
for field in ('number', 'timestamp', 'hash'):
    good = dict(number='0x64', timestamp=hex(NOW), hash='0x' + f'{100:064x}')
    missing = good.copy()
    del missing[field]
    BAD_BLOCKS.append(missing)
    for bad in (None, {}, [], 42, True, '', 'garbage', '-0x1', '64', '0x'):
        BAD_BLOCKS.append(dict(good, **{field: bad}))


@pytest.mark.parametrize('stage', ['initial', 'final'])
@pytest.mark.parametrize('bad', BAD_BLOCKS)
def test_malformed_snapshot_is_controlled_error(stage, bad):
    class BadBlock(Synthetic):
        def call(self, method, params):
            if method == 'eth_getBlockByNumber' and params[0] == ('latest' if stage == 'initial' else '0x64'):
                return copy.deepcopy(bad)
            return super().call(method, params)

    with pytest.raises(RpcError, match='malformed snapshot block'):
        inspect(OWNER, BadBlock(), from_block=80)


@pytest.mark.parametrize('field', ['number', 'timestamp', 'hash'])
def test_final_snapshot_must_match_initial(field):
    class Changed(Synthetic):
        def call(self, method, params):
            result = super().call(method, params)
            if method == 'eth_getBlockByNumber' and params[0] == '0x64':
                result[field] = '0x' + 'ab'*32 if field == 'hash' else '0x65'
            return result

    with pytest.raises(RpcError, match='reorganized'):
        inspect(OWNER, Changed(), from_block=80)


@pytest.mark.parametrize('error_type', [requests.HTTPError, requests.ConnectionError, requests.Timeout, ValueError])
def test_transport_and_cli_omit_endpoint_secrets(error_type, capsys):
    endpoint = 'https://example.invalid/v3/REGATE_FAKE_KEY?key=SECRET'
    rpc = HttpTransport(endpoint)
    error = error_type('failed request to ' + endpoint)
    response = Mock()
    if error_type is ValueError:
        response.json.side_effect = error
    else:
        response.raise_for_status.side_effect = error
    with patch.object(rpc.session, 'post', return_value=response):
        with pytest.raises(RpcError) as caught:
            rpc.call('eth_chainId', [])
        assert str(caught.value) == f'RPC request failed: {error_type.__name__}'
        assert caught.value.__cause__ is error
        with patch('eth_guard.cli.HttpTransport', return_value=rpc):
            assert main(['inspect', OWNER, '--rpc', endpoint]) == 1
    stderr = capsys.readouterr().err
    assert f'RPC request failed: {error_type.__name__}' in stderr
    for secret in (endpoint, 'example.invalid', 'REGATE_FAKE_KEY', 'SECRET'):
        assert secret not in stderr
