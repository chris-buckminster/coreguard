import logging
import socket
import ssl
import struct

import httpx

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


def resolve_upstream(request_data: bytes, config: Config) -> bytes:
    """Route to the appropriate upstream resolver with fallback."""
    try:
        if config.upstream_mode == "doh":
            return resolve_doh(request_data, config.upstream_dns, config.upstream_timeout)
        elif config.upstream_mode == "dot":
            return resolve_dot(
                request_data, config.upstream_dns, timeout=config.upstream_timeout
            )
        else:
            return resolve_plain(
                request_data, config.upstream_fallback, timeout=config.upstream_timeout
            )
    except Exception as e:
        # Fall back to plain DNS if DoH/DoT fails
        if config.upstream_mode != "plain":
            logger.warning("Upstream %s failed (%s), falling back to plain DNS", config.upstream_mode, e)
            return resolve_plain(
                request_data, config.upstream_fallback, timeout=config.upstream_timeout
            )
        raise
