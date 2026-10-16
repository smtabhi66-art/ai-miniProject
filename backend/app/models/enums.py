"""Enumerations shared by all models.

Enums inherit from ``str`` so they serialize to JSON as plain strings.
"""
from enum import Enum


class DeviceType(str, Enum):
    WORKSTATION = "workstation"
    ADMIN_WORKSTATION = "admin_workstation"
    SERVER = "server"
    DATABASE = "database"
    ROUTER = "router"
    FIREWALL = "firewall"
    EXTERNAL = "external"


class DeviceStatus(str, Enum):
    """Operational status: what the network is *doing* with the device."""

    ONLINE = "online"
    RESTRICTED = "restricted"  # only service-essential links remain active
    ISOLATED = "isolated"      # all links cut (simulated)
    OFFLINE = "offline"


class ThreatLevel(str, Enum):
    """The agent's *belief* about a device, produced by threat detection."""

    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    CRITICAL = "critical"


class LinkStatus(str, Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"


class EventType(str, Enum):
    NORMAL_TRAFFIC = "normal_traffic"
    FAILED_LOGIN = "failed_login"
    SUCCESSFUL_LOGIN = "successful_login"
    PORT_SCAN = "port_scan"
    UNUSUAL_TRAFFIC = "unusual_traffic"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    ESCALATED = "escalated"  # no safe automated response; needs a human


# Devices in these states cannot send, receive or forward traffic.
NON_TRAVERSABLE = frozenset({DeviceStatus.ISOLATED, DeviceStatus.OFFLINE})
