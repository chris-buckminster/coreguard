import asyncio
import logging
import socket
import ssl
import struct

import httpx
from dnslib import DNSRecord, EDNS0

from coreguard.config import Config

logger = logging.getLogger("coreguard.upstream")

_doh_client: httpx.Client | None = None


def _get_doh_client(timeout: float = 5.0) -> httpx.Client:
    global _doh_client
    if _doh_client is None:
        _doh_client = httpx.Client(http2=True, timeout=timeout)
    return _doh_client


def close_doh_client() -> None:
    """Close the persistent DoH client."""
    global _doh_client
    if _doh_client is not None:
        _doh_client.close()
        _doh_client = None


def resolve_plain(request_data: bytes, server: str, port: int = 53, timeout: float = 5.0) -> bytes:
    """Forward DNS query via plain UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request_data, (server, port))
        response_data, _ = sock.recvfrom(4096)
        return response_data
    finally:
        sock.close()


def resolve_doh(request_data: bytes, doh_url: str, timeout: float = 5.0) -> bytes:
    """Forward DNS query via DNS-over-HTTPS (RFC 8484 wireformat POST)."""
    client = _get_doh_client(timeout)
    response = client.post(
        doh_url,
        content=request_data,
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        },
    )
    response.raise_for_status()
    return response.content


def resolve_dot(request_data: bytes, server: str, port: int = 853, timeout: float = 5.0) -> bytes:
    """Forward DNS query via DNS-over-TLS (RFC 7858)."""
    ctx = ssl.create_default_context()
    with socket.create_connection((server, port), timeout=timeout) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=server) as sock:
            # DNS over TCP: prefix with 2-byte length
            tcp_msg = struct.pack("!H", len(request_data)) + request_data
            sock.sendall(tcp_msg)
            # Read 2-byte length prefix
            length_data = _recv_exact(sock, 2)
            resp_length = struct.unpack("!H", length_data)[0]
            return _recv_exact(sock, resp_length)


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading DNS response")
        data += chunk
    return data


class DNSSECError(Exception):
    """Raised when DNSSEC validation fails in strict mode."""
    pass


def prepare_dnssec_request(request_data: bytes) -> bytes:
    """Add EDNS0 OPT record with DO (DNSSEC OK) bit to a DNS request."""
    record = DNSRecord.parse(request_data)
    edns = EDNS0(flags="do", udp_len=4096)
    record.add_ar(edns)
    return record.pack()


def check_dnssec_response(response_data: bytes, strict: bool) -> bytes:
    """Check the AD (Authenticated Data) flag on a DNS response.

    In strict mode, raises DNSSECError if AD is not set.
    """
    record = DNSRecord.parse(response_data)
    if strict and not record.header.ad:
        raise DNSSECError("DNSSEC validation failed: AD bit not set")
    return response_data


def resolve_doq(request_data: bytes, server: str, port: int = 853, timeout: float = 5.0) -> bytes:
    """Forward DNS query via DNS-over-QUIC (RFC 9250)."""
    from aioquic.quic.configuration import QuicConfiguration

    async def _doq_query() -> bytes:
        from aioquic.asyncio import connect

        configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
        configuration.verify_mode = ssl.CERT_REQUIRED

        async with connect(server, port, configuration=configuration) as protocol:
            stream_id = protocol._quic.get_next_available_stream_id()
            # DNS-over-QUIC uses 2-byte length prefix like DoT
            tcp_msg = struct.pack("!H", len(request_data)) + request_data
            protocol._quic.send_stream_data(stream_id, tcp_msg, end_stream=True)
            protocol.transmit()

            # Wait for response
            data = b""
            waiter = asyncio.get_event_loop().create_future()

            def stream_data_received(event_stream_id, event_data, end_stream):
                nonlocal data
                if event_stream_id == stream_id:
                    data += event_data
                    if end_stream and not waiter.done():
                        waiter.set_result(None)

            protocol._quic._events_handler = stream_data_received

            await asyncio.wait_for(waiter, timeout=timeout)

            # Strip 2-byte length prefix
            if len(data) < 2:
                raise ConnectionError("Incomplete DoQ response")
            resp_length = struct.unpack("!H", data[:2])[0]
            return data[2:2 + resp_length]

    return asyncio.run(_doq_query())


def resolve_upstream(request_data: bytes, config: Config) -> bytes:
    """Route to upstream resolvers with multi-provider failover.

    Tries each provider in order with the configured mode. If all fail,
    falls back to plain DNS with each provider before giving up.
    """
    errors: list[Exception] = []

    # Prepare request with DNSSEC DO bit if enabled
    wire_data = request_data
    if config.dnssec_enabled:
        wire_data = prepare_dnssec_request(request_data)

    def _post_process(response: bytes) -> bytes:
        """Apply DNSSEC response checking if enabled."""
        if config.dnssec_enabled:
            return check_dnssec_response(response, config.dnssec_strict)
        return response

    # Try each provider with the configured mode
    for provider in config.upstream_providers:
        try:
            if config.upstream_mode == "doh":
                return _post_process(resolve_doh(wire_data, provider.doh, config.upstream_timeout))
            elif config.upstream_mode == "dot":
                return _post_process(resolve_dot(wire_data, provider.dot, timeout=config.upstream_timeout))
            elif config.upstream_mode == "doq":
                if not provider.doq:
                    raise ValueError(f"Provider {provider.name} has no DoQ endpoint")
                return _post_process(resolve_doq(wire_data, provider.doq, timeout=config.upstream_timeout))
            else:
                return _post_process(resolve_plain(wire_data, provider.plain, timeout=config.upstream_timeout))
        except DNSSECError:
            raise  # Don't retry on DNSSEC failures — the response itself is untrusted
        except Exception as e:
            logger.warning("Provider %s (%s) failed: %s", provider.name, config.upstream_mode, e)
            errors.append(e)

    # All providers failed with primary mode — try plain DNS fallback
    if config.upstream_mode != "plain":
        for provider in config.upstream_providers:
            try:
                logger.warning("Falling back to plain DNS via %s", provider.name)
                return _post_process(resolve_plain(wire_data, provider.plain, timeout=config.upstream_timeout))
            except DNSSECError:
                raise
            except Exception as e:
                errors.append(e)

    # Everything failed
    raise errors[-1] if errors else RuntimeError("No upstream providers configured")
