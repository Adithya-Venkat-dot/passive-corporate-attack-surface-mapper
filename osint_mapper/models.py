from dataclasses import dataclass, field


@dataclass(frozen=True)
class Asset:
    value: str
    source: str
    risk: str = "Low"
    reason: str = ""


@dataclass
class ScanResult:
    domain: str
    subdomains: list[Asset] = field(default_factory=list)
    emails: list[Asset] = field(default_factory=list)
    historical_urls: list[Asset] = field(default_factory=list)
    harvester_hosts: list[Asset] = field(default_factory=list)
    harvester_ips: list[Asset] = field(default_factory=list)
    source_status: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def high_risk_assets(self) -> list[Asset]:
        assets = self.subdomains + self.historical_urls + self.harvester_hosts + self.harvester_ips
        return [asset for asset in assets if asset.risk in {"High", "Critical"}]
