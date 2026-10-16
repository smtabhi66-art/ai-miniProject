"""Central configuration: file locations and tunable constants."""
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "data"
TOPOLOGY_DIR = DATA_DIR / "topologies"
SCENARIO_DIR = DATA_DIR / "scenarios"
RULES_DIR = DATA_DIR / "rules"

DEFAULT_TOPOLOGY = "enterprise_default"
DEFAULT_SEED = 42

# How many past ticks of evidence the state manager keeps per device.
EVIDENCE_RETENTION_TICKS = 10
