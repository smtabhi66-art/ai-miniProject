"""Network model: devices, links, services and the agent's internal NetworkState.

The network graph is stored as an explicit adjacency list::

    adjacency = {"R1": [Link(R1-WS1), Link(R1-R2), ...], "WS1": [Link(R1-WS1)], ...}

Each undirected Link object is placed in *both* endpoints' lists, so changing
``link.status`` once updates the edge in both directions.
"""
from dataclasses import dataclass, field
from typing import Any, Iterator

from app.models.enums import (
    NON_TRAVERSABLE,
    DeviceStatus,
    DeviceType,
    LinkStatus,
    ThreatLevel,
)
from app.models.events import Evidence
from app.models.incident import Incident


@dataclass
class Device:
    id: str
    name: str
    type: DeviceType
    zone: str
    ip: str                 # simulated label only
    criticality: int        # 1 (low) .. 5 (crown jewel)
    trust_level: float      # 0.0 .. 1.0, static
    services: list[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0.0 .. 1.0, updated by threat detection
    status: DeviceStatus = DeviceStatus.ONLINE
    threat_level: ThreatLevel = ThreatLevel.NORMAL
    monitored: bool = False  # extra logging enabled by increase_monitoring

    @property
    def is_traversable(self) -> bool:
        return self.status not in NON_TRAVERSABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "zone": self.zone,
            "ip": self.ip,
            "criticality": self.criticality,
            "trust_level": self.trust_level,
            "services": list(self.services),
            "risk_score": self.risk_score,
            "status": self.status.value,
            "threat_level": self.threat_level.value,
            "monitored": self.monitored,
        }


@dataclass
class Link:
    source: str
    target: str
    latency_cost: float  # base traversal cost, > 0
    risk: float          # 0.0 .. 1.0 inherent risk of the link
    status: LinkStatus = LinkStatus.ACTIVE

    @property
    def is_active(self) -> bool:
        return self.status is LinkStatus.ACTIVE

    def other(self, device_id: str) -> str:
        if device_id == self.source:
            return self.target
        if device_id == self.target:
            return self.source
        raise ValueError(f"{device_id} is not an endpoint of link {self.source}-{self.target}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "latency_cost": self.latency_cost,
            "risk": self.risk,
            "status": self.status.value,
        }


@dataclass
class Service:
    name: str
    hosts: list[str]
    critical: bool
    depends_on: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "hosts": list(self.hosts),
            "critical": self.critical,
            "depends_on": list(self.depends_on),
        }


@dataclass
class NetworkState:
    """The agent's internal model of the world at one tick."""

    devices: dict[str, Device] = field(default_factory=dict)
    adjacency: dict[str, list[Link]] = field(default_factory=dict)
    services: dict[str, Service] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    tick: int = 0
    evidence: dict[str, Evidence] = field(default_factory=dict)
    facts: set[tuple[str, ...]] = field(default_factory=set)
    incidents: dict[str, Incident] = field(default_factory=dict)

    # ---- construction -------------------------------------------------
    def add_device(self, device: Device) -> None:
        if device.id in self.devices:
            raise ValueError(f"duplicate device id: {device.id}")
        self.devices[device.id] = device
        self.adjacency[device.id] = []

    def add_link(self, link: Link) -> None:
        for end in (link.source, link.target):
            if end not in self.devices:
                raise ValueError(f"link {link.source}-{link.target} references unknown device {end}")
        if link.source == link.target:
            raise ValueError(f"self-loop on {link.source}")
        if self.get_link(link.source, link.target) is not None:
            raise ValueError(f"duplicate link {link.source}-{link.target}")
        self.adjacency[link.source].append(link)
        self.adjacency[link.target].append(link)

    def add_service(self, service: Service) -> None:
        if service.name in self.services:
            raise ValueError(f"duplicate service: {service.name}")
        self.services[service.name] = service

    # ---- graph queries ------------------------------------------------
    def get_link(self, a: str, b: str) -> Link | None:
        for link in self.adjacency.get(a, []):
            if link.other(a) == b:
                return link
        return None

    def links(self) -> Iterator[Link]:
        """Each undirected link exactly once."""
        for device_id, links in self.adjacency.items():
            for link in links:
                if link.source == device_id:
                    yield link

    def neighbors(self, device_id: str, usable_only: bool = True) -> list[str]:
        """Adjacent device ids.

        With ``usable_only`` (the default), blocked links and isolated/offline
        neighbours are skipped, which is what traffic and search can actually use.
        """
        if device_id not in self.adjacency:
            raise KeyError(f"unknown device: {device_id}")
        result = []
        for link in self.adjacency[device_id]:
            other = link.other(device_id)
            if usable_only and (not link.is_active or not self.devices[other].is_traversable):
                continue
            result.append(other)
        return result

    # ---- serialization ------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "tick": self.tick,
            "metadata": dict(self.metadata),
            "devices": [d.to_dict() for d in self.devices.values()],
            "links": [link.to_dict() for link in self.links()],
            "services": [s.to_dict() for s in self.services.values()],
            "facts": [list(f) for f in sorted(self.facts)],
            "incidents": [i.to_dict() for i in self.incidents.values()],
        }
