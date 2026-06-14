"""Tests for the scan pipeline orchestration (fully offline, fakes injected)."""

from vulnscan.ai.chains import ChainedFinding
from vulnscan.domain.enums import Severity
from vulnscan.domain.schemas import FindingBase
from vulnscan.scanners.base import ScanResult
from vulnscan.workers.pipeline import ScanPipeline, ScanRequest
from vulnscan.workers.state import InMemoryScanStateStore

TARGET = "https://example.com/"


# --------------------------------------------------------------------------- #
# Doubles
# --------------------------------------------------------------------------- #
class _FakeScanner:
    def __init__(self, result: ScanResult):
        self._result = result

    async def safe_run(self) -> ScanResult:
        return self._result


class FakeScannerFactory:
    def __init__(self, results: dict):
        self.results = results
        self.seen: dict = {}

    def recon(self, target):
        return _FakeScanner(self.results["recon"])

    def http_headers(self, target):
        return _FakeScanner(self.results["http"])

    def js_secrets(self, target, script_urls):
        self.seen["scripts"] = script_urls
        return _FakeScanner(self.results["js"])

    def form_fuzzer(self, target, forms):
        self.seen["forms"] = forms
        return _FakeScanner(self.results["fuzz"])

    async def aclose(self):
        pass


class FakeEngine:
    """Returns one finding per category call and one chain per chain-call."""

    async def analyze(self, *, system, evidence_label, evidence, context, schema=FindingBase):
        if schema is ChainedFinding:
            return [
                ChainedFinding(
                    title="Info leak enables injection",
                    severity=Severity.HIGH,
                    cvss_score=8.1,
                    description="F1 + F2 combine.",
                    chain_parent_ids=["F1", "F2"],
                )
            ]
        return [
            FindingBase(
                title=f"finding from {evidence_label}",
                severity=Severity.LOW,
                cvss_score=2.0,
                description="d",
            )
        ]


def _results() -> dict:
    recon = ScanResult(
        scanner="recon",
        target=TARGET,
        data={
            "tech_stack": ["nginx", "WordPress"],
            "scripts": ["https://example.com/app.js"],
            "forms": [
                {
                    "action": "https://example.com/login",
                    "method": "post",
                    "inputs": [{"name": "u", "type": "text"}, {"name": "p", "type": "password"}],
                },
                {
                    "action": "https://example.com/search",
                    "method": "get",
                    "inputs": [{"name": "q", "type": "text"}],
                },
            ],
            "links": {
                "internal": ["https://example.com/admin", "https://example.com/about"],
                "external": [],
            },
        },
    )
    return {
        "recon": recon,
        "http": ScanResult(scanner="http_headers", target=TARGET, data={"missing": []}),
        "js": ScanResult(scanner="js_secrets", target=TARGET, data={"matches": []}),
        "fuzz": ScanResult(scanner="form_fuzzer", target=TARGET, data={"probes": []}),
    }


def _request(level: int) -> ScanRequest:
    return ScanRequest(
        scan_id="scan-1",
        tenant_id="tenant-1",
        target_url=TARGET,
        scope_domains=["example.com"],
        scan_level=level,
    )


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
async def test_full_pipeline_level_6():
    factory = FakeScannerFactory(_results())
    state = InMemoryScanStateStore()
    result = await ScanPipeline().run(
        _request(6), scanner_factory=factory, engine=FakeEngine(), state=state
    )

    assert result.completed_step == 6
    assert result.tech_stack == ["nginx", "WordPress"]
    assert len(result.findings) == 3  # header + js + xss
    assert len(result.chained_findings) == 1  # F1+F2 chain survives
    assert result.report["total_findings"] == 4
    assert result.report["max_severity"] == "high"

    # Active testing fed on recon-discovered scripts and prioritized forms.
    assert factory.seen["scripts"] == ["https://example.com/app.js"]
    assert factory.seen["forms"][0]["action"].endswith("/login")  # password form first

    # Every step persisted intermediate state keyed by scan_id (§4).
    keys = set((await state.all("scan-1")).keys())
    assert keys == {
        "recon",
        "surface",
        "active_http",
        "active_js",
        "active_fuzz",
        "findings",
        "chained_findings",
        "report",
    }


async def test_scan_level_1_recon_only():
    factory = FakeScannerFactory(_results())
    state = InMemoryScanStateStore()
    result = await ScanPipeline().run(
        _request(1), scanner_factory=factory, engine=FakeEngine(), state=state
    )
    assert result.completed_step == 1
    assert result.findings == []
    assert result.chained_findings == []
    assert result.report is None
    assert set((await state.all("scan-1")).keys()) == {"recon"}
    assert "scripts" not in factory.seen  # active testing never ran


async def test_scan_level_3_active_no_analysis():
    factory = FakeScannerFactory(_results())
    state = InMemoryScanStateStore()
    result = await ScanPipeline().run(
        _request(3), scanner_factory=factory, engine=FakeEngine(), state=state
    )
    assert result.completed_step == 3
    assert result.findings == []  # analysis (step 4) not reached
    assert "active_fuzz" in await state.all("scan-1")


async def test_surface_mapping_prioritizes_risky():
    factory = FakeScannerFactory(_results())
    state = InMemoryScanStateStore()
    await ScanPipeline().run(_request(2), scanner_factory=factory, engine=FakeEngine(), state=state)
    surface = await state.get("scan-1", "surface")
    # Login (password input) ranks before the plain search form.
    assert surface["priority_forms"][0]["action"].endswith("/login")
    # /admin link flagged as a risky endpoint.
    assert "https://example.com/admin" in surface["risky_endpoints"]
