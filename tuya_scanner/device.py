"""Tuya device data model."""

from dataclasses import dataclass, field


@dataclass
class TuyaDevice:
    """Represents a discovered Tuya device."""

    ip: str
    gwId: str = ""
    active: int = 0
    ability: int = 0
    mode: int = 0
    encrypt: bool = False
    productKey: str = ""
    version: str = ""
    token: bool = False
    wf_cfg: bool = False
    port: int = 6668
    source: str = "broadcast"
    extra: dict = field(default_factory=dict)

    def __str__(self) -> str:
        parts = [f"IP: {self.ip}"]
        if self.gwId:
            parts.append(f"ID: {self.gwId}")
        if self.productKey:
            parts.append(f"ProductKey: {self.productKey}")
        if self.version:
            parts.append(f"Version: {self.version}")
        parts.append(f"Encrypted: {self.encrypt}")
        parts.append(f"Source: {self.source}")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "gwId": self.gwId,
            "active": self.active,
            "ability": self.ability,
            "mode": self.mode,
            "encrypt": self.encrypt,
            "productKey": self.productKey,
            "version": self.version,
            "token": self.token,
            "wf_cfg": self.wf_cfg,
            "port": self.port,
            "source": self.source,
            **self.extra,
        }
