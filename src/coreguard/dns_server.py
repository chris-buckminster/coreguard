import logging

from dnslib import QTYPE, RR, A, AAAA, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from coreguard.cache import DNSCache
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
        cache: DNSCache | None = None,
    ) -> None:
        self.filter = domain_filter
        self.config = config
        self.stats = stats
        self.query_logger = query_logger
        self.cache = cache

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        qtype_int = request.q.qtype

        # 1. Check blocklist (always checked first so new blocks take effect immediately)
        if self.filter.is_blocked(qname):
            reply = self._make_block_reply(request, qname, qtype_int)
            self.stats.record_query(qname, blocked=True)
            self.query_logger.log_query(qname, qtype, blocked=True)
            if self.cache:
                self.cache.put(qname, qtype_int, reply, is_blocked=True)
            return reply

        # 2. Check cache
        if self.cache:
            cached = self.cache.get(qname, qtype_int)
            if cached is not None:
                cached.header.id = request.header.id
                self.stats.record_query(qname, blocked=False)
                self.stats.record_cache_hit()
                self.query_logger.log_query(qname, qtype, blocked=False)
                return cached
            self.stats.record_cache_miss()

        # 3. Forward to upstream
        try:
            raw_request = request.pack()
            raw_response = resolve_upstream(raw_request, self.config)
            response = DNSRecord.parse(raw_response)
            response.header.id = request.header.id
        except Exception as e:
            logger.error("Upstream resolution failed for %s: %s", qname, e)
            reply = request.reply()
            reply.header.rcode = 2  # SERVFAIL
            self.stats.record_query(qname, blocked=False, error=True)
            return reply

        # 4. Check CNAME chain for blocked targets
        if self.config.cname_check_enabled:
            blocked_target = self._check_cname_chain(response)
            if blocked_target:
                logger.info("CNAME block: %s -> %s", qname, blocked_target)
                reply = self._make_block_reply(request, qname, qtype_int)
                self.stats.record_query(qname, blocked=True)
                self.stats.record_cname_block()
                self.query_logger.log_query(qname, qtype, blocked=True)
                if self.cache:
                    self.cache.put(qname, qtype_int, reply, is_blocked=True)
                return reply

        # 5. Cache and return
        if self.cache and response.header.rcode == 0:
            self.cache.put(qname, qtype_int, response)
        self.stats.record_query(qname, blocked=False)
        self.query_logger.log_query(qname, qtype, blocked=False)
        return response

    def _make_block_reply(self, request: DNSRecord, qname: str, qtype_int: int) -> DNSRecord:
        """Build a block response."""
        reply = request.reply()
        if qtype_int == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
        elif qtype_int == QTYPE.AAAA:
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=300))
        return reply

    def _check_cname_chain(self, response: DNSRecord) -> str | None:
        """Check CNAME targets in the response against the blocklist.

        Returns the first blocked target, or None if all are clean.
        """
        checked = 0
        for rr in response.rr:
            if rr.rtype == QTYPE.CNAME:
                target = str(rr.rdata).rstrip(".")
                checked += 1
                if checked > self.config.cname_max_depth:
                    break
                if self.filter.is_blocked(target):
                    return target
        return None


def start_dns_server(
    config: Config,
    domain_filter: DomainFilter,
    stats: Stats,
    query_logger: QueryLogger,
) -> tuple[DNSServer, DNSServer, DNSCache | None]:
    """Create and start UDP + TCP DNS servers. Returns (udp_server, tcp_server, cache)."""
    cache = None
    if config.cache_enabled:
        cache = DNSCache(
            max_entries=config.cache_max_entries,
            max_ttl=config.cache_max_ttl,
            min_ttl=config.cache_min_ttl,
        )

    resolver = BlockingResolver(domain_filter, config, stats, query_logger, cache)

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
    return udp_server, tcp_server, cache
