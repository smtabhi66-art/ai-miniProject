"""Milestone 1 smoke test: confirms the package layout imports and pytest is wired up."""
import importlib

PACKAGES = [
    "app",
    "app.api",
    "app.core",
    "app.models",
    "app.simulation",
    "app.state",
    "app.agent",
    "app.storage",
    "app.algorithms.search",
    "app.algorithms.csp",
    "app.algorithms.logic",
    "app.algorithms.planning",
]


def test_packages_import():
    for name in PACKAGES:
        assert importlib.import_module(name) is not None, name
