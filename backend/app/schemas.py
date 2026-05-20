from pydantic import BaseModel


class ScanRequest(BaseModel):
    target: str


class AssetItem(BaseModel):
    type: str
    value: str
    risk: str


class FindingItem(BaseModel):
    title: str
    severity: str
    score: float
    description: str


class ScanResponse(BaseModel):
    target: str
    status: str
    scanned_at: str
    summary: dict
    assets: list[AssetItem]
    findings: list[FindingItem]