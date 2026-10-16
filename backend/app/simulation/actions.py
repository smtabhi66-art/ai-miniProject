"""Simulated defensive actions.

Every action is a precondition check plus an effect on a NetworkState. They only
change Python objects. Nothing here touches a real network.

The preconditions here are about *validity*: does the link exist, is the device
already isolated? Whether an action is *wise* (for example, isolating the only
auth server) is decided later by the CSP and the planners.
"""
from dataclasses import dataclass
from typing import Any, Callable

from app.models.enums import DeviceStatus, DeviceType, LinkStatus
from app.models.network import Device, Link, NetworkState
from app.state.state_manager import StateManager, Transition

Params = dict[str, Any]


class ActionError(ValueError):
    """The action's preconditions are not met in the current state."""


@dataclass(frozen=True)
class ActionSpec:
    name: str
    params: tuple[str, ...]
    description: str
    check: Callable[[NetworkState, Params], None]
    effect: Callable[[NetworkState, Params], None]


def _device(state: NetworkState, params: Params) -> Device:
    device_id = params["device"]
    if device_id not in state.devices:
        raise ActionError(f"unknown device: {device_id}")
    return state.devices[device_id]


def _internal_device(state: NetworkState, params: Params) -> Device:
    device = _device(state, params)
    if device.type is DeviceType.EXTERNAL:
        raise ActionError(f"{device.id} is outside the organisation; block its link instead")
    return device


def _link(state: NetworkState, params: Params) -> Link:
    link = state.get_link(params["a"], params["b"])
    if link is None:
        raise ActionError(f"no link between {params['a']} and {params['b']}")
    return link


def _require_status(device: Device, *allowed: DeviceStatus) -> None:
    if device.status not in allowed:
        names = "/".join(s.value for s in allowed)
        raise ActionError(f"{device.id} is {device.status.value}, must be {names}")


# ---- preconditions ------------------------------------------------------
def _check_isolate(state: NetworkState, p: Params) -> None:
    _require_status(_internal_device(state, p), DeviceStatus.ONLINE, DeviceStatus.RESTRICTED)


def _check_restrict(state: NetworkState, p: Params) -> None:
    _require_status(_internal_device(state, p), DeviceStatus.ONLINE)


def _check_restore(state: NetworkState, p: Params) -> None:
    _require_status(_internal_device(state, p), DeviceStatus.ISOLATED, DeviceStatus.RESTRICTED)


def _check_remediate(state: NetworkState, p: Params) -> None:
    # A machine must be cut off before it is cleaned.
    _require_status(_internal_device(state, p), DeviceStatus.ISOLATED)


def _check_reset_credentials(state: NetworkState, p: Params) -> None:
    _internal_device(state, p)


def _check_monitoring(state: NetworkState, p: Params) -> None:
    device = _device(state, p)
    if device.monitored:
        raise ActionError(f"{device.id} is already monitored")


def _check_block(state: NetworkState, p: Params) -> None:
    if not _link(state, p).is_active:
        raise ActionError(f"link {p['a']}-{p['b']} is already blocked")


def _check_unblock(state: NetworkState, p: Params) -> None:
    if _link(state, p).is_active:
        raise ActionError(f"link {p['a']}-{p['b']} is not blocked")


# ---- effects ------------------------------------------------------------
def _set_status(status: DeviceStatus) -> Callable[[NetworkState, Params], None]:
    def effect(state: NetworkState, p: Params) -> None:
        state.devices[p["device"]].status = status
    return effect


def _set_link(status: LinkStatus) -> Callable[[NetworkState, Params], None]:
    def effect(state: NetworkState, p: Params) -> None:
        state.get_link(p["a"], p["b"]).status = status
    return effect


def _monitor(state: NetworkState, p: Params) -> None:
    state.devices[p["device"]].monitored = True


def _no_visible_effect(state: NetworkState, p: Params) -> None:
    """Remediation and credential resets change hidden ground truth only (see environment.py)."""


ACTIONS: dict[str, ActionSpec] = {spec.name: spec for spec in [
    ActionSpec("isolate_device", ("device",), "Cut the device off from every link",
               _check_isolate, _set_status(DeviceStatus.ISOLATED)),
    ActionSpec("restrict_device", ("device",), "Allow only its service traffic; block outbound attacks",
               _check_restrict, _set_status(DeviceStatus.RESTRICTED)),
    ActionSpec("restore_device", ("device",), "Return an isolated/restricted device to normal",
               _check_restore, _set_status(DeviceStatus.ONLINE)),
    ActionSpec("remediate_device", ("device",), "Clean an isolated device (simulated re-image)",
               _check_remediate, _no_visible_effect),
    ActionSpec("reset_credentials", ("device",), "Reset passwords/keys used on the device",
               _check_reset_credentials, _no_visible_effect),
    ActionSpec("increase_monitoring", ("device",), "Enable detailed logging for the device",
               _check_monitoring, _monitor),
    ActionSpec("block_link", ("a", "b"), "Block traffic on one link",
               _check_block, _set_link(LinkStatus.BLOCKED)),
    ActionSpec("unblock_link", ("a", "b"), "Re-enable a blocked link",
               _check_unblock, _set_link(LinkStatus.ACTIVE)),
]}


def validate_action(state: NetworkState, name: str, params: Params) -> ActionSpec:
    spec = ACTIONS.get(name)
    if spec is None:
        raise ActionError(f"unknown action: {name}")
    missing = [p for p in spec.params if p not in params]
    if missing:
        raise ActionError(f"{name} is missing parameter(s): {', '.join(missing)}")
    spec.check(state, params)
    return spec


def apply_action(state: NetworkState, name: str, params: Params) -> None:
    """Validate, then mutate ``state`` in place."""
    validate_action(state, name, params).effect(state, params)


def execute_action(manager: StateManager, name: str, params: Params) -> Transition:
    """Validate against the manager's state, then apply as a recorded transition."""
    spec = validate_action(manager.state, name, params)
    return manager.apply(name, params, lambda s: spec.effect(s, params))
