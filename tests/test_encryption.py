"""Tests for encryption of findings at rest (CLAUDE.md §7.4).

The headline guarantee: sensitive finding content is ciphertext in the database
and only ever plaintext in the application. We prove it by reading the raw column
values with a typeless ``text()`` query (which bypasses the decrypting column
type) and asserting they are NOT the plaintext, while the ORM read returns the
original values.
"""

import uuid

from cryptography.fernet import Fernet
from sqlalchemy import text

from vulnscan.domain.encryption import EncryptedJSON, EncryptedString, Encryptor
from vulnscan.domain.enums import ScanStatus, Severity
from vulnscan.domain.models import ScanFinding, ScanJob, Tenant


# --------------------------------------------------------------------------- #
# Encryptor unit behaviour
# --------------------------------------------------------------------------- #
def test_encryptor_roundtrip():
    enc = Encryptor([Fernet.generate_key().decode()])
    token = enc.encrypt("reflected XSS in /login")
    assert token != "reflected XSS in /login"
    assert enc.decrypt(token) == "reflected XSS in /login"


def test_encryptor_is_non_deterministic():
    # Fernet embeds a random IV + timestamp, so two encryptions differ.
    enc = Encryptor([Fernet.generate_key().decode()])
    assert enc.encrypt("same") != enc.encrypt("same")


def test_key_rotation_decrypts_old_ciphertext():
    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()
    old = Encryptor([old_key])
    token = old.encrypt("secret PoC")

    # New ring: new key encrypts, but the old key is still trusted to decrypt.
    rotated = Encryptor([new_key, old_key])
    assert rotated.decrypt(token) == "secret PoC"
    # And new writes use the new key (still decryptable by the ring).
    assert rotated.decrypt(rotated.encrypt("fresh")) == "fresh"


def test_encrypted_types_back_onto_text():
    # Both decorators persist as Text (ciphertext is longer than the plaintext
    # and, for JSON, no longer valid JSON).
    from sqlalchemy import Text

    assert isinstance(EncryptedString().impl, Text)
    assert isinstance(EncryptedJSON().impl, Text)


# --------------------------------------------------------------------------- #
# At-rest guarantee through the real ORM/DB round trip
# --------------------------------------------------------------------------- #
async def _seed_finding(session) -> uuid.UUID:
    tenant = Tenant(name="Acme")
    session.add(tenant)
    await session.flush()
    job = ScanJob(
        tenant_id=tenant.id,
        user_id=tenant.id,  # any uuid; users table not needed for this column test
        target_url="https://example.com/",
        status=ScanStatus.COMPLETED,
        scan_level=6,
    )
    session.add(job)
    await session.flush()
    finding = ScanFinding(
        tenant_id=tenant.id,
        scan_job_id=job.id,
        title="SQL injection in /search",
        severity=Severity.HIGH,
        cvss_score=8.2,
        description="Boolean-based blind SQLi via the q parameter.",
        proof_of_concept="q=1' OR '1'='1",
        recommendation="Use parameterized queries.",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
    )
    session.add(finding)
    await session.commit()
    return finding.id


async def test_finding_content_is_ciphertext_at_rest(session):
    await _seed_finding(session)  # exactly one finding in this in-memory DB

    # Raw, typeless read — bypasses the decrypting column type.
    row = (
        await session.execute(
            text(
                'SELECT title, description, proof_of_concept, recommendation, "references" '
                "FROM scan_findings"
            )
        )
    ).one()
    raw_title, raw_desc, raw_poc, raw_rec, raw_refs = row

    # None of the sensitive fields are stored in the clear.
    assert "SQL injection" not in raw_title
    assert "Boolean-based" not in raw_desc
    assert "OR '1'='1" not in raw_poc
    assert "parameterized" not in raw_rec
    assert "cwe.mitre.org" not in raw_refs
    # references is no longer plaintext JSON.
    assert not raw_refs.strip().startswith("[")


async def test_finding_decrypts_transparently_through_orm(session):
    finding_id = await _seed_finding(session)
    session.expire_all()  # force a fresh DB read, not the identity-map cache

    finding = await session.get(ScanFinding, finding_id)
    assert finding.title == "SQL injection in /search"
    assert finding.description.startswith("Boolean-based blind SQLi")
    assert finding.proof_of_concept == "q=1' OR '1'='1"
    assert finding.recommendation == "Use parameterized queries."
    assert finding.references == ["https://cwe.mitre.org/data/definitions/89.html"]
    # Plaintext, queryable classification fields are unaffected.
    assert finding.severity == Severity.HIGH
    assert finding.cvss_score == 8.2
