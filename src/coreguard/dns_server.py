import logging

from dnslib import QTYPE, RR, A, AAAA, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from coreguard.config import Config
from coreguard.filtering import DomainFilter
from coreguard.logging_config import QueryLogger
from coreguard.stats import Stats
from coreguard.upstream import resolve_upstream

logger = logging.getLogger("coreguard.dns")


class BlockingResolver(BaseResolver):
    """DNS resolver that blocks domains matching the filter."""

    def __init__(
        self,
        domain_filter: DomainFilter,
        config: Config,
        stats: Stats,
        query_logger: QueryLogger,
    ) -> None:
        self.filter = domain_filter
        self.config = config
        self.stats = stats
        self.query_logger = query_logger

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]

        if self.filter.is_blocked(qname):
            reply = request.reply()
            if request.q.qtype == QTYPE.A:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
            elif request.q.qtype == QTYPE.AAAA:
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=300))
            # For other qtypes, return empty NOERROR
            self.stats.record_query(qname, blocked=True)
            self.query_logger.log_query(qname, qtype, blocked=True)
            return reply

        # Forward to upstream
        try:
            raw_request = request.pack()
            raw_response = resolve_upstream(raw_request, self.config)
            response = DNSRecord.parse(raw_response)
            response.header.id = request.header.id
            self.stats.record_query(qname, blocked=False)
            self.query_logger.log_query(qname, qtype, blocked=False)
            return response
        except Exception as e:
            logger.error("Upstream resolution failed for %s: %s", qname, e)
            reply = request.reply()
            reply.header.rcode = 2  # SERVFAIL
            self.stats.record_query(qname, blocked=False, error=True)
            return reply


def start_dns_server(
    config: Config,
    domain_filter: DomainFilter,
    stats: Stats,
    query_logger: QueryLogger,
) -> tuple[DNSServer, DNSServer]:
    """Create and start UDP + TCP DNS servers. Returns (udp_server, tcp_server)."""
    resolver = BlockingResolver(domain_filter, config, stats, query_logger)

    udp_server = DNSServer(
        resolver, port=config.listen_port, address=config.listen_address
    )
    tcp_server = DNSServer(
        resolver, port=config.listen_port, address=config.listen_address, tcp=True
    )

    udp_server.start_thread()
    tcp_server.start_thread()

    logger.info(
        "DNS server listening on %s:%d (UDP+TCP)",
        config.listen_address,
        config.listen_port,
    )
    return udp_server, tcp_server
