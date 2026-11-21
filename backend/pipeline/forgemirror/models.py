"""Pydantic models for pipeline stage outputs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ComponentInfo(BaseModel):
    name: str | None = None
    exported: bool | None = None
    process: str | None = None
    authorities: str | None = None


class ComponentCounts(BaseModel):
    activities: int = 0
    services: int = 0
    receivers: int = 0
    providers: int = 0


class ManifestInfo(BaseModel):
    package: str | None = None
    application: str | None = None
    app_component_factory: str | None = None
    activities: list[ComponentInfo] = Field(default_factory=list)
    services: list[ComponentInfo] = Field(default_factory=list)
    receivers: list[ComponentInfo] = Field(default_factory=list)
    providers: list[ComponentInfo] = Field(default_factory=list)

    def counts(self) -> ComponentCounts:
        return ComponentCounts(
            activities=len(self.activities),
            services=len(self.services),
            receivers=len(self.receivers),
            providers=len(self.providers),
        )


class DexEntry(BaseModel):
    name: str
    size: int
    sha256: str
    version: str | None = None
    valid: bool = True
    source: str = "base"


class LibEntry(BaseModel):
    path: str
    abi_dir: str
    arch: str | None = None
    size: int
    sha256: str
    source: str = "base"


class AssetEntry(BaseModel):
    path: str
    size: int
    sha256: str


class Anomaly(BaseModel):
    kind: str
    detail: str


class IntakeResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_id: str = Field(default="forgemirror.intake/1", alias="schema")
    ok: bool
    build_id: str
    profile: str
    signing_mode: str
    reason_codes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    apk: str
    apk_sha256: str = ""
    package: str | None = None
    version_code: int | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    cert_sha256: str | None = None
    application: str | None = None
    app_component_factory: str | None = None
    abis: list[str] = Field(default_factory=list)
    split_count: int = 0
    split_names: list[str] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)


class Inventory(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_id: str = Field(default="forgemirror.inventory/1", alias="schema")
    package: str
    version_code: int
    version_name: str | None = None
    min_sdk: int
    target_sdk: int | None = None
    abis: list[str] = Field(default_factory=list)
    dex: list[DexEntry] = Field(default_factory=list)
    libs: list[LibEntry] = Field(default_factory=list)
    assets: list[AssetEntry] = Field(default_factory=list)
    application: str | None = None
    app_component_factory: str | None = None
    components: ComponentCounts = Field(default_factory=ComponentCounts)
    providers: list[ComponentInfo] = Field(default_factory=list)
    anomalies: list[Anomaly] = Field(default_factory=list)
    fingerprint: dict[str, str | int] = Field(default_factory=dict)
    apk_sha256: str
    split_names: list[str] = Field(default_factory=list)
