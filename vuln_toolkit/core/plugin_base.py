from __future__ import annotations

import abc
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


class TargetType(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BOTH = "both"


@dataclass
class Finding:
    plugin: str
    title: str
    severity: Severity
    target: str
    category: str = "general"
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class BasePlugin(abc.ABC):
    """Every detection module must subclass this and be decorated with @register."""

    name: str = "base"
    description: str = ""
    target_type: TargetType = TargetType.BOTH
    version: str = "0.1.0"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    @abc.abstractmethod
    def run(self, target: str) -> list[Finding]:
        """Execute the check against a path (offline) or host/URL (online)."""

    def supports(self, mode: TargetType) -> bool:
        return self.target_type in (mode, TargetType.BOTH)


_REGISTRY: dict[str, type[BasePlugin]] = {}


def register(cls: type[BasePlugin]) -> type[BasePlugin]:
    """Class decorator that registers a plugin under its `name`."""
    if not issubclass(cls, BasePlugin):
        raise TypeError(f"{cls.__name__} must subclass BasePlugin")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"Plugin name collision: '{cls.name}'")
    _REGISTRY[cls.name] = cls
    return cls


def get_registry() -> dict[str, type[BasePlugin]]:
    return dict(_REGISTRY)