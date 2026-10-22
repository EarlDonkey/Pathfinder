from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Lower index = lower severity. Renderers use this for stable ordering.
SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


class TargetType(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BOTH = "both"


@dataclass
class ScanContext:
    """Shared state passed from one plugin to the next during a single scan."""
    target: str
    mode: TargetType
    state: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    plugin: str
    title: str
    severity: Severity
    target: str
    id: str = ""
    category: str = "general"
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    cve: str | None = None
    kev: bool | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.plugin}|{self.file or ''}|{self.line or ''}|{self.title}|{self.cve or ''}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class BasePlugin(abc.ABC):
    """Contract every detection module implements. Register with @register."""

    name: str = "base"
    description: str = ""
    target_type: TargetType = TargetType.BOTH
    version: str = "0.1.0"
    priority: int = 100  # lower runs first: port-scan=10, web=30, bandit=50, audit=60, enrich=200

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abc.abstractmethod
    def run(self, target: str, context: ScanContext | None = None) -> list[Finding]:
        """Execute the check. `target` is a filesystem path (offline) or host/URL (online)."""

    def supports(self, mode: TargetType) -> bool:
        return self.target_type in (mode, TargetType.BOTH)


_REGISTRY: dict[str, type[BasePlugin]] = {}


def register(cls: type[BasePlugin]) -> type[BasePlugin]:
    if not issubclass(cls, BasePlugin):
        raise TypeError(f"{cls.__name__} must subclass BasePlugin")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"Plugin name collision: '{cls.name}'")
    _REGISTRY[cls.name] = cls
    return cls


def get_registry() -> dict[str, type[BasePlugin]]:
    return dict(_REGISTRY)