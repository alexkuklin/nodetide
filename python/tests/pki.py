"""A throwaway PKI for tests: CA hierarchy and qualified-style signer certificates.

Nothing here is real: names are invented and the keys exist only in memory.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID, ObjectIdentifier

from nodetide.eidas.certs import (
    QC_COMPLIANCE, QC_SSCD, QC_STATEMENTS_OID, QC_TYPE, QC_TYPE_ESIGN,
    QCStatement, QCStatements, QcTypes,
)

DAY = dt.timedelta(days=1)


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _name(common_name: str, **extra: str) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, extra.pop("country", "BG")),
             x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if "given" in extra:
        attrs.append(x509.NameAttribute(NameOID.GIVEN_NAME, extra.pop("given")))
    if "surname" in extra:
        attrs.append(x509.NameAttribute(NameOID.SURNAME, extra.pop("surname")))
    if "serial" in extra:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, extra.pop("serial")))
    return x509.Name(attrs)


@dataclass
class Ca:
    cert: x509.Certificate
    key: object
    parent: "Ca | None" = None

    @property
    def asn1(self) -> asn1_x509.Certificate:
        return asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))


def aia(url: str) -> x509.AuthorityInformationAccess:
    return x509.AuthorityInformationAccess([x509.AccessDescription(
        AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(url))])


def make_ca(common_name: str, parent: Ca | None = None, years: int = 10, path_length: int | None = None,
            aia_url: str | None = None) -> Ca:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _name(common_name)
    issuer_name = parent.cert.subject if parent else subject
    signing_key = parent.key if parent else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - DAY).not_valid_after(now() + years * 365 * DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if parent:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(parent.key.public_key()), critical=False)
    if aia_url:
        builder = builder.add_extension(aia(aia_url), critical=False)
    return Ca(builder.sign(signing_key, hashes.SHA256()), key, parent)


def qc_statements(qualified: bool, qscd: bool, esign: bool = True) -> bytes:
    statements = []
    if qualified:
        statements.append(QCStatement({"statement_id": QC_COMPLIANCE}))
    if qscd:
        statements.append(QCStatement({"statement_id": QC_SSCD}))
    if esign:
        statements.append(QCStatement({"statement_id": QC_TYPE, "statement_info": QcTypes([QC_TYPE_ESIGN])}))
    return QCStatements(statements).dump()


@dataclass
class Leaf:
    cert: x509.Certificate
    key: object
    ca: Ca

    @property
    def asn1(self) -> asn1_x509.Certificate:
        return asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))


def make_signer_cert(
    ca: Ca,
    given: str = "Maria",
    surname: str = "Ivanova",
    *,
    qualified: bool = True,
    qscd: bool = True,
    non_repudiation: bool = True,
    key_kind: str = "rsa",
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    crl_url: str | None = None,
    common_name: str | None = None,
    aia_url: str | None = None,
    serial: str = "PNOBG-0000000000",
) -> Leaf:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if key_kind == "rsa" \
        else ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name or f"{given} {surname}", given=given, surname=surname, serial=serial))
        .issuer_name(ca.cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now() - DAY).not_valid_after(not_after or now() + 365 * DAY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=non_repudiation, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
        .add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier(QC_STATEMENTS_OID), qc_statements(qualified, qscd)),
            critical=False)
    )
    if aia_url:
        builder = builder.add_extension(aia(aia_url), critical=False)
    if crl_url:
        builder = builder.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(crl_url)], relative_name=None, reasons=None,
            crl_issuer=None)]), critical=False)
    return Leaf(builder.sign(ca.key, hashes.SHA256()), key, ca)


def make_crl(ca: Ca, revoked: list[Leaf], this_update: dt.datetime | None = None) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.cert.subject)
        .last_update(this_update or now() - dt.timedelta(hours=1))
        .next_update(now() + 7 * DAY)
    )
    for leaf in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.cert.serial_number).revocation_date(now() - dt.timedelta(hours=2)).build())
    return builder.sign(ca.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class SoftwareSigner:
    """A Signer backed by an in-memory key (stands in for a PKCS#11 token)."""

    def __init__(self, leaf: Leaf, hash_alg: str = "sha256", extra_chain: list[Ca] | None = None):
        self.leaf = leaf
        self.certificate = leaf.asn1
        self.chain = [c.asn1 for c in (extra_chain if extra_chain is not None else [leaf.ca])]
        self.hash_alg = hash_alg

    def sign(self, data: bytes) -> bytes:
        hash_cls = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[self.hash_alg]()
        if isinstance(self.leaf.key, rsa.RSAPrivateKey):
            return self.leaf.key.sign(data, padding.PKCS1v15(), hash_cls)
        return self.leaf.key.sign(data, ec.ECDSA(hash_cls))
