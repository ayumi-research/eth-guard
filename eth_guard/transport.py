"""Read-only JSON-RPC boundary; transports can be injected for offline use."""
from typing import Protocol, Any
import requests

READ_METHODS = frozenset({'eth_chainId', 'eth_getBlockByNumber', 'eth_getCode',
                          'eth_getLogs', 'eth_call'})

class RpcError(RuntimeError):
    pass

class Transport(Protocol):
    def call(self, method: str, params: list) -> Any: ...

class HttpTransport:
    def __init__(self, url: str, timeout: float = 30):
        if not url.startswith(('https://', 'http://')):
            raise ValueError('RPC URL must use HTTP(S)')
        self.url, self.timeout, self._id = url, timeout, 0
        self.session = requests.Session()

    def call(self, method: str, params: list):
        if method not in READ_METHODS:
            raise ValueError(f'RPC method is not allowed: {method}')
        self._id += 1
        try:
            response = self.session.post(self.url, json={
                'jsonrpc': '2.0', 'id': self._id, 'method': method, 'params': params},
                timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise RpcError('RPC HTTP/JSON request failed') from exc
        if not isinstance(body, dict) or body.get('id') != self._id or body.get('jsonrpc') != '2.0':
            raise RpcError('Invalid JSON-RPC response envelope')
        if 'error' in body:
            # Do not echo provider URLs/credentials into reports.
            raise RpcError(f'RPC {method} returned an error')
        if 'result' not in body:
            raise RpcError('Missing JSON-RPC result')
        return body['result']
