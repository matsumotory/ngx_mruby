"""The HTTP/3 client of the suite (HttpVersions in test/t/client.rb).

Sends one request over HTTP/3 (QUIC) with aioquic and prints the response
as one JSON object:

    python3 _h3_client.py HOST PORT SERVERNAME < request.json

The request on stdin is a JSON object with "method", "path", "authority",
"headers" (a list of [name, value]) and "body" (base64). The output has
"status" (an Integer), "headers" (a list of [name, value] in the order of
the response, without the pseudo-headers), "body" (base64) and "alpn" (the
protocol that the TLS handshake chose). The certificate of the server is
not verified: the test nginx has a self-signed one. SERVERNAME is sent as
the TLS server name (SNI). The exit status is 1 when the request failed or
did not end within 30 seconds, with the reason on stderr.

test.sh installs aioquic (test/h3/requirements.txt) and passes its
directory to the tests in TEST_SH_H3_PYTHONPATH ("HTTP/2 and HTTP/3" in
docs/test/README.md).
"""

import asyncio
import base64
import json
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent

TIMEOUT = 30


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3 = H3Connection(self._quic)
        self.waiter = None
        self.response = {"status": None, "headers": [], "trailers": [], "body": b""}
        self.stream_id = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated) and self.waiter and not self.waiter.done():
            self.waiter.set_exception(RuntimeError("connection closed: %s" % event.reason_phrase))
            return
        for h3_event in self.h3.handle_event(event):
            if getattr(h3_event, "stream_id", None) != self.stream_id:
                continue
            if isinstance(h3_event, HeadersReceived):
                if self.response["status"] is None:
                    for name, value in h3_event.headers:
                        if name == b":status":
                            self.response["status"] = int(value)
                        elif not name.startswith(b":"):
                            self.response["headers"].append([name, value])
                else:
                    self.response["trailers"].extend([name, value] for name, value in h3_event.headers)
            elif isinstance(h3_event, DataReceived):
                self.response["body"] += h3_event.data
            if h3_event.stream_ended and not self.waiter.done():
                self.waiter.set_result(None)

    async def request(self, req):
        self.stream_id = self._quic.get_next_available_stream_id()
        body = base64.b64decode(req.get("body", ""))
        headers = [
            (b":method", req["method"].encode()),
            (b":scheme", b"https"),
            (b":authority", req["authority"].encode()),
            (b":path", req["path"].encode()),
        ] + [(k.lower().encode(), v.encode()) for k, v in req.get("headers", [])]
        self.waiter = self._loop.create_future()
        self.h3.send_headers(self.stream_id, headers, end_stream=not body)
        if body:
            self.h3.send_data(self.stream_id, body, end_stream=True)
        self.transmit()
        await self.waiter
        return self.response


async def main(host, port, servername, req):
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=servername)
    configuration.verify_mode = ssl.CERT_NONE
    async with connect(host, port, configuration=configuration, create_protocol=Client) as client:
        response = await client.request(req)
        response["alpn"] = client._quic.tls.alpn_negotiated
        client.close()
        return response


def encode(response):
    def text(pairs):
        return [[k.decode("latin-1"), v.decode("latin-1")] for k, v in pairs]

    return {
        "status": response["status"],
        "headers": text(response["headers"]),
        "trailers": text(response["trailers"]),
        "body": base64.b64encode(response["body"]).decode(),
        "alpn": response["alpn"],
    }


if __name__ == "__main__":
    host, port, servername = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    req = json.load(sys.stdin)
    try:
        response = asyncio.run(asyncio.wait_for(main(host, port, servername, req), TIMEOUT))
    except Exception as e:  # noqa: BLE001 - the reason goes to the test
        print("h3_client: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(encode(response)))
