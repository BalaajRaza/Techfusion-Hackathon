"""Stage 4 - temporal entity resolution.

IP-to-host and IP-to-user bindings are only valid for a time window (DHCP
lease, VPN session), so every edge of the graph carries valid_from /
valid_until plus the citation that proves it. resolve() never merges two
candidates silently: a conflict is returned as ambiguous with both listed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import networkx as nx
from pydantic import BaseModel, Field

from ..models import Citation, Event
from .references import Asset, DirUser, References, is_internal_ip

FAR_PAST = datetime(1970, 1, 1, tzinfo=timezone.utc)
FAR_FUTURE = datetime(2999, 1, 1, tzinfo=timezone.utc)


class VpnSession(BaseModel):
    session: str
    user: Optional[str]
    src_ip: Optional[str]
    geo: Optional[str]
    assigned_ip: Optional[str]
    mfa: Optional[str]
    start: datetime
    end: Optional[datetime] = None
    auth_event: str
    end_event: Optional[str] = None
    bytes_to_client: Optional[int] = None
    bytes_from_client: Optional[int] = None
    duration_s: Optional[int] = None


class Lease(BaseModel):
    ip: str
    hostname: Optional[str]
    start: datetime
    end: Optional[datetime]
    citation: Citation


class Resolution(BaseModel):
    ip: str
    kind: str  # asset | vpn_session | external | unknown_internal
    hostname: Optional[str] = None
    user: Optional[str] = None
    session: Optional[str] = None
    confidence: str = "LOW"
    ambiguous: bool = False
    candidates: list[str] = Field(default_factory=list)
    note: str = ""
    citations: list[Citation] = Field(default_factory=list)


class EntityGraph:
    def __init__(self, refs: References, events: list[Event]):
        self.refs = refs
        self.g = nx.MultiDiGraph()
        self.sessions: dict[str, VpnSession] = {}
        self.leases: list[Lease] = []
        self._events = {e.id: e for e in events}
        self._build(events)

    # ------------------------------------------------------------------ build
    def _edge(self, src: str, dst: str, relation: str, citation: Citation, valid_from: Optional[datetime] = None,
              valid_until: Optional[datetime] = None, confidence: str = "HIGH") -> None:
        self.g.add_edge(src, dst, relation=relation, valid_from=valid_from, valid_until=valid_until,
                        confidence=confidence, citation=citation.ref)

    def _build(self, events: list[Event]) -> None:
        r = self.refs
        for a in r.assets:
            self.g.add_node(f"host:{a.hostname}", entity_type="HOSTNAME", criticality=a.criticality, asset_type=a.type, owner=a.owner)
            self.g.add_node(f"tag:{a.tag}", entity_type="ASSET_TAG")
            self._edge(f"tag:{a.tag}", f"host:{a.hostname}", "identifies", a.citation)
            for ip in a.ips:
                self.g.add_node(f"ip:{ip}", entity_type="IP")
                self._edge(f"host:{a.hostname}", f"ip:{ip}", "inventory_ip", a.citation)
            for ip in a.public_ips:
                self.g.add_node(f"ip:{ip}", entity_type="IP")
                self._edge(f"host:{a.hostname}", f"ip:{ip}", "public_ip", a.citation)
        for u in r.users:
            self.g.add_node(f"user:{u.username}", entity_type="USER", full_name=u.full_name, role=u.role)
            if r.asset_by_tag(u.laptop_tag):
                self._edge(f"user:{u.username}", f"tag:{u.laptop_tag}", "assigned_laptop", u.citation)

        live = [e for e in events if e.parse_status == "parsed" and not any(f.startswith("DUPLICATE_OF") for f in e.flags)]
        for e in live:
            if e.action == "dhcp_ack" and e.ip_source and e.ts_utc:
                lease = Lease(ip=e.ip_source, hostname=e.fields.get("hostname"), start=e.ts_utc, end=e.ts_end_utc, citation=e.cite())
                self.leases.append(lease)
                host = f"host:{lease.hostname}"
                self.g.add_node(host, entity_type="HOSTNAME")
                self.g.add_node(f"ip:{lease.ip}", entity_type="IP")
                self._edge(host, f"ip:{lease.ip}", "dhcp_lease", lease.citation, lease.start, lease.end)
            elif e.action == "vpn_auth" and e.outcome == "SUCCESS" and e.fields.get("session") and e.ts_utc:
                sid = e.fields["session"]
                self.sessions[sid] = VpnSession(session=sid, user=e.user_account, src_ip=e.ip_source, geo=e.fields.get("geo"),
                                                assigned_ip=e.fields.get("assigned_ip"), mfa=e.fields.get("mfa"), start=e.ts_utc, auth_event=e.id)
        for e in live:
            if e.action == "vpn_session_end":
                s = self.sessions.get(e.fields.get("session", ""))
                if s:
                    s.end, s.end_event = e.ts_utc, e.id
                    s.bytes_to_client, s.bytes_from_client = e.fields.get("bytes_to_client"), e.fields.get("bytes_from_client")
                    s.duration_s = e.fields.get("duration_s")
        for s in self.sessions.values():
            cite = self._events[s.auth_event].cite()
            if s.user and s.assigned_ip:
                self.g.add_node(f"user:{s.user}", entity_type="USER")
                self.g.add_node(f"ip:{s.assigned_ip}", entity_type="IP")
                self._edge(f"user:{s.user}", f"ip:{s.assigned_ip}", "vpn_assigned_ip", cite, s.start, s.end)
            if s.user and s.src_ip:
                self.g.add_node(f"ip:{s.src_ip}", entity_type="IP", external=True)
                self._edge(f"user:{s.user}", f"ip:{s.src_ip}", "vpn_login_from", cite, s.start, s.end)

    # ---------------------------------------------------------------- lookups
    def session(self, sid: Optional[str]) -> Optional[VpnSession]:
        return self.sessions.get(sid or "")

    def session_at(self, ip: str, ts: datetime) -> Optional[VpnSession]:
        for s in self.sessions.values():
            if s.assigned_ip == ip and s.start <= ts <= (s.end or FAR_FUTURE):
                return s
        return None

    def leases_for(self, ip: str) -> list[Lease]:
        return [ls for ls in self.leases if ls.ip == ip]

    def lease_at(self, ip: str, ts: datetime) -> Optional[Lease]:
        active = [ls for ls in self.leases_for(ip) if ls.start <= ts <= (ls.end or FAR_FUTURE)]
        return max(active, key=lambda ls: ls.start) if active else None

    def owner_of(self, hostname: Optional[str]) -> Optional[DirUser]:
        a = self.refs.asset_by_name(hostname)
        if not a:
            return None
        return next((u for u in self.refs.users if u.laptop_tag == a.tag), None)

    def laptop_of(self, username: Optional[str]) -> Optional[Asset]:
        u = self.refs.user(username)
        return self.refs.asset_by_tag(u.laptop_tag) if u else None

    def resolve(self, ip: Optional[str], ts: Optional[datetime]) -> Resolution:
        """Who or what held this IP at this moment?"""
        if not ip:
            return Resolution(ip="", kind="unknown_internal", note="no address")
        r = self.refs
        ts = ts or FAR_PAST
        if r.in_vpn_pool(ip):
            s = self.session_at(ip, ts)
            cites = [r.vpn_pool_citation] if r.vpn_pool_citation else []
            if s:
                return Resolution(ip=ip, kind="vpn_session", user=s.user, session=s.session, confidence="HIGH",
                                  citations=[self._events[s.auth_event].cite()] + cites,
                                  note=f"VPN pool address assigned to session {s.session}")
            return Resolution(ip=ip, kind="vpn_session", confidence="LOW", citations=cites,
                              note="VPN pool address with no session covering this time")
        asset = r.asset_by_ip(ip)
        lease = self.lease_at(ip, ts)
        has_leases = bool(self.leases_for(ip))
        if asset and lease and lease.hostname and r.asset_by_name(lease.hostname) is asset:
            u = self.owner_of(asset.hostname)
            return Resolution(ip=ip, kind="asset", hostname=asset.hostname, user=u.username if u else None, confidence="HIGH",
                              citations=[lease.citation, asset.citation] + ([u.citation] if u else []),
                              note="DHCP lease and asset inventory agree")
        if asset and lease and lease.hostname:
            return Resolution(ip=ip, kind="asset", hostname=lease.hostname, confidence="MEDIUM", ambiguous=True,
                              candidates=[lease.hostname, asset.hostname], citations=[lease.citation, asset.citation],
                              note=f"AMBIGUOUS: the DHCP lease gives {lease.hostname} but the inventory lists {asset.hostname} for this address")
        if asset:
            u = self.owner_of(asset.hostname)
            cites = [asset.citation] + ([u.citation] if u else [])
            if has_leases and ip not in asset.public_ips:
                return Resolution(ip=ip, kind="asset", hostname=asset.hostname, user=u.username if u else None, confidence="MEDIUM",
                                  citations=cites, note="inventory match, but outside every recorded DHCP lease window")
            return Resolution(ip=ip, kind="asset", hostname=asset.hostname, user=u.username if u else None, confidence="HIGH",
                              citations=cites, note="asset inventory exact match")
        if lease and lease.hostname:
            known = r.asset_by_name(lease.hostname)
            return Resolution(ip=ip, kind="asset", hostname=lease.hostname, confidence="MEDIUM", citations=[lease.citation],
                              note="DHCP lease only" + ("" if known else "; hostname is not in the asset inventory"))
        if is_internal_ip(ip):
            return Resolution(ip=ip, kind="unknown_internal", confidence="LOW", note="internal address that is not in the asset inventory")
        return Resolution(ip=ip, kind="external", confidence="HIGH", note="external address")

    # ----------------------------------------------------------------- export
    def export(self) -> dict[str, Any]:
        nodes = [dict(id=n, **d) for n, d in self.g.nodes(data=True)]
        edges = []
        for s, t, d in self.g.edges(data=True):
            edges.append(dict(source=s, target=t, relation=d["relation"], confidence=d["confidence"], citation=d["citation"],
                              valid_from=d["valid_from"].isoformat() if d["valid_from"] else None,
                              valid_until=d["valid_until"].isoformat() if d["valid_until"] else None))
        return dict(nodes=nodes, edges=edges,
                    vpn_sessions=[s.model_dump(mode="json") for s in self.sessions.values()],
                    dhcp_leases=[ls.model_dump(mode="json") for ls in self.leases])
