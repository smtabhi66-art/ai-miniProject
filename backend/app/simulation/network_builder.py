"""Build a validated NetworkState from a topology JSON file.

Run directly to print a summary of the default topology::

    python -m app.simulation.network_builder
"""
import json
from pathlib import Path
from typing import Any

from app.core.config import DEFAULT_TOPOLOGY, TOPOLOGY_DIR
from app.core.logging_setup import get_logger
from app.models.enums import DeviceType
from app.models.network import Device, Link, NetworkState, Service

log = get_logger(__name__)


class TopologyError(ValueError):
    """Raised when a topology file is malformed or inconsistent."""


def load_topology(name_or_path: str | Path = DEFAULT_TOPOLOGY) -> NetworkState:
    """Load by name (``"enterprise_default"``) or by path to a ``.json`` file."""
    path = Path(name_or_path)
    if path.suffix != ".json":
        path = TOPOLOGY_DIR / f"{name_or_path}.json"
    if not path.is_file():
        raise TopologyError(f"topology file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TopologyError(f"invalid JSON in {path.name}: {exc}") from exc
    state = build_network(data)
    log.debug("Loaded topology %s: %d devices, %d links, %d services",
             path.name, len(state.devices), sum(1 for _ in state.links()), len(state.services))
    return state


def build_network(data: dict[str, Any]) -> NetworkState:
    state = NetworkState(metadata=dict(data.get("metadata", {})))
    try:
        for raw in data["devices"]:
            state.add_device(_parse_device(raw))
        for raw in data["links"]:
            state.add_link(_parse_link(raw))
        for raw in data.get("services", []):
            state.add_service(Service(
                name=raw["name"],
                hosts=list(raw["hosts"]),
                critical=bool(raw["critical"]),
                depends_on=list(raw.get("depends_on", [])),
            ))
    except KeyError as exc:
        raise TopologyError(f"missing required field {exc}") from exc
    except ValueError as exc:
        raise TopologyError(str(exc)) from exc
    _validate_services(state)
    admin = state.metadata.get("admin_device")
    if admin is not None and admin not in state.devices:
        raise TopologyError(f"admin_device {admin} is not a device")
    return state


def _parse_device(raw: dict[str, Any]) -> Device:
    device = Device(
        id=raw["id"],
        name=raw["name"],
        type=DeviceType(raw["type"]),
        zone=raw["zone"],
        ip=raw["ip"],
        criticality=int(raw["criticality"]),
        trust_level=float(raw["trust_level"]),
        services=list(raw.get("services", [])),
    )
    if not 1 <= device.criticality <= 5:
        raise ValueError(f"{device.id}: criticality must be 1..5")
    if not 0.0 <= device.trust_level <= 1.0:
        raise ValueError(f"{device.id}: trust_level must be 0..1")
    return device


def _parse_link(raw: dict[str, Any]) -> Link:
    link = Link(
        source=raw["source"],
        target=raw["target"],
        latency_cost=float(raw["latency_cost"]),
        risk=float(raw["risk"]),
    )
    if link.latency_cost <= 0:
        raise ValueError(f"link {link.source}-{link.target}: latency_cost must be > 0")
    if not 0.0 <= link.risk <= 1.0:
        raise ValueError(f"link {link.source}-{link.target}: risk must be 0..1")
    return link


def _validate_services(state: NetworkState) -> None:
    """Service hosts and each device's ``services`` list must agree."""
    for service in state.services.values():
        if not service.hosts:
            raise TopologyError(f"service {service.name} has no hosts")
        for host in service.hosts:
            if host not in state.devices:
                raise TopologyError(f"service {service.name} host {host} is not a device")
            if service.name not in state.devices[host].services:
                raise TopologyError(f"{host} hosts {service.name} but does not list it")
        for dep in service.depends_on:
            if dep not in state.services:
                raise TopologyError(f"service {service.name} depends on unknown service {dep}")
    for device in state.devices.values():
        for name in device.services:
            if name not in state.services or device.id not in state.services[name].hosts:
                raise TopologyError(f"{device.id} lists service {name} it is not a host of")


def summary(state: NetworkState) -> str:
    lines = [f"Topology: {state.metadata.get('name', '?')}", "", "Devices:"]
    for d in state.devices.values():
        svc = f" services={d.services}" if d.services else ""
        lines.append(f"  {d.id:<7} {d.type.value:<18} zone={d.zone:<9} crit={d.criticality}{svc}")
    lines += ["", "Adjacency list:"]
    for device_id, links in state.adjacency.items():
        lines.append(f"  {device_id:<7} -> {', '.join(link.other(device_id) for link in links)}")
    lines += ["", "Services:"]
    for s in state.services.values():
        lines.append(f"  {s.name:<5} hosts={s.hosts} critical={s.critical} depends_on={s.depends_on}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary(load_topology()))
