"""CAdES-BES detached signatures over a statement, built and parsed with asn1crypto.

Building takes a Signer, so the private key can live on a PKCS#11 token (the key
never leaves it) or in software (tests). Parsing and checking the signature
itself is plain public-key cryptography; trust in the certificate is separate
(see verify.py).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from asn1crypto import algos, cms, core, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# --- ESS signing-certificate-v2 (RFC 5035), which asn1crypto does not define ------

SIGNING_CERT_V2_OID = "1.2.840.113549.1.9.16.2.47"


class ESSCertIDv2(core.Sequence):
    _fields = [
        ("hash_algorithm", algos.DigestAlgorithm, {"default": {"algorithm": "sha256"}}),
        ("cert_hash", core.OctetString),
        ("issuer_serial", cms.IssuerSerial, {"optional": True}),
    ]


class ESSCertIDv2s(core.SequenceOf):
    _child_spec = ESSCertIDv2


class SigningCertificateV2(core.Sequence):
    _fields = [
        ("certs", ESSCertIDv2s),
        ("policies", core.Any, {"optional": True}),
    ]


class SetOfSigningCertificateV2(core.SetOf):
    _child_spec = SigningCertificateV2


# Older CAdES-BES signers (and some national signing applications) still emit
# ESS signingCertificate (RFC 2634), which identifies the certificate by SHA-1.
SIGNING_CERT_V1_OID = "1.2.840.113549.1.9.16.2.12"


class ESSCertID(core.Sequence):
    _fields = [
        ("cert_hash", core.OctetString),
        ("issuer_serial", cms.IssuerSerial, {"optional": True}),
    ]


class ESSCertIDs(core.SequenceOf):
    _child_spec = ESSCertID


class SigningCertificateV1(core.Sequence):
    _fields = [
        ("certs", ESSCertIDs),
        ("policies", core.Any, {"optional": True}),
    ]


class SetOfSigningCertificateV1(core.SetOf):
    _child_spec = SigningCertificateV1


cms.CMSAttributeType._map[SIGNING_CERT_V1_OID] = "signing_certificate"
cms.CMSAttribute._oid_specs["signing_certificate"] = SetOfSigningCertificateV1


cms.CMSAttributeType._map[SIGNING_CERT_V2_OID] = "signing_certificate_v2"
cms.CMSAttribute._oid_specs["signing_certificate_v2"] = SetOfSigningCertificateV2

# --- algorithms -----------------------------------------------------------------------

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
MIN_RSA_BITS = 2048


class CmsError(ValueError):
    """The CMS structure or signature is invalid."""


class Signer(Protocol):
    """Produces signatures with the signer certificate's private key."""

    certificate: x509.Certificate
    chain: list[x509.Certificate]  # intermediates to include (not the leaf, not the root)
    hash_alg: str  # sha256 | sha384 | sha512

    def sign(self, data: bytes) -> bytes:
        """RSA PKCS#1 v1.5 over `data` hashed with hash_alg, or an ECDSA DER signature."""


def _signature_algorithm(cert: x509.Certificate, hash_alg: str) -> algos.SignedDigestAlgorithm:
    kind = cert.public_key.algorithm  # 'rsa' | 'ec' | ...
    if kind == "rsa":
        return algos.SignedDigestAlgorithm({"algorithm": f"{hash_alg}_rsa"})
    if kind == "ec":
        return algos.SignedDigestAlgorithm({"algorithm": f"{hash_alg}_ecdsa"})
    raise CmsError(f"unsupported key type: {kind}")


def create_cades_detached(
    content: bytes,
    signer: Signer,
    signing_time: datetime | None = None,
    *,
    legacy_ess: bool = False,
    include_signing_time: bool = True,
) -> bytes:
    """DER ContentInfo(SignedData) with a detached CAdES-BES signature over `content`.

    legacy_ess / include_signing_time reproduce what some other signing
    applications emit (ESS signingCertificate with a SHA-1 id; no signingTime).
    """
    hash_alg = signer.hash_alg
    if hash_alg not in _HASHES:
        raise CmsError(f"unsupported hash {hash_alg}")
    signing_time = signing_time or datetime.now(timezone.utc)
    cert = signer.certificate

    if legacy_ess:
        cert_attr = cms.CMSAttribute({"type": "signing_certificate", "values": [SigningCertificateV1({
            "certs": [ESSCertID({"cert_hash": hashlib.sha1(cert.dump()).digest()})],
        })]})
    else:
        cert_attr = cms.CMSAttribute({"type": "signing_certificate_v2", "values": [SigningCertificateV2({
            "certs": [ESSCertIDv2({
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_alg}),
                "cert_hash": hashlib.new(hash_alg, cert.dump()).digest(),
            })],
        })]})
    attributes = [
        cms.CMSAttribute({"type": "content_type", "values": [cms.ContentType("data")]}),
        cms.CMSAttribute({"type": "message_digest",
                          "values": [core.OctetString(hashlib.new(hash_alg, content).digest())]}),
        cert_attr,
    ]
    if include_signing_time:
        attributes.append(
            cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": signing_time})]})
        )
    attrs = cms.CMSAttributes(attributes)
    signature = signer.sign(attrs.dump())  # SET OF, as RFC 5652 section 5.4 requires

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": cert.issuer, "serial_number": cert.serial_number})}),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": hash_alg}),
        "signed_attrs": attrs,
        "signature_algorithm": _signature_algorithm(cert, hash_alg),
        "signature": signature,
    })
    certificates = [cms.CertificateChoices({"certificate": cert})] + [
        cms.CertificateChoices({"certificate": c}) for c in signer.chain
    ]
    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": hash_alg})],
        "encap_content_info": {"content_type": "data"},  # no content: detached
        "certificates": certificates,
        "signer_infos": [signer_info],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()


@dataclass
class ParsedCades:
    signer_cert: x509.Certificate
    other_certs: list[x509.Certificate]
    hash_alg: str
    signing_time: datetime | None
    signed_attrs: dict = field(default_factory=dict)


def _public_key(cert: x509.Certificate):
    return serialization.load_der_public_key(cert.public_key.dump())


def verify_cades_detached(der: bytes, content: bytes) -> ParsedCades:
    """Check a detached CAdES-BES signature over `content`; return what was signed.

    Verifies: structure, the message digest, the signature over the signed
    attributes, and that the signer certificate is the one the signature names
    (ESS signing-certificate-v2 when present, otherwise issuer and serial).
    Does NOT decide whether the certificate is trusted.
    """
    try:
        info = cms.ContentInfo.load(der)
        if info["content_type"].native != "signed_data":
            raise CmsError("not a SignedData structure")
        data = info["content"]
        if data["encap_content_info"]["content"].native is not None:
            raise CmsError("signature is not detached")
        signer_infos = data["signer_infos"]
        if len(signer_infos) != 1:
            raise CmsError("exactly one signer is required")
        signer_info = signer_infos[0]
        certs = [c.chosen for c in (data["certificates"] or []) if c.name == "certificate"]
    except CmsError:
        raise
    except Exception as e:
        raise CmsError(f"cannot parse CMS: {type(e).__name__}") from None

    sid = signer_info["sid"]
    if sid.name != "issuer_and_serial_number":
        raise CmsError("only issuer-and-serial signer identifiers are supported")
    issuer, serial = sid.chosen["issuer"], sid.chosen["serial_number"].native
    signer_cert = next(
        (c for c in certs if c.serial_number == serial and c.issuer == issuer), None
    )
    if signer_cert is None:
        raise CmsError("the signer certificate is not included in the signature")

    hash_alg = signer_info["digest_algorithm"]["algorithm"].native
    if hash_alg not in _HASHES:
        raise CmsError(f"digest algorithm {hash_alg} is not accepted")
    if signer_info["signed_attrs"].native is None:
        raise CmsError("signed attributes are required")
    attrs = {a["type"].native: a["values"] for a in signer_info["signed_attrs"]}
    for required in ("content_type", "message_digest"):
        if required not in attrs:
            raise CmsError(f"missing signed attribute: {required}")
    if "signing_certificate_v2" not in attrs and "signing_certificate" not in attrs:
        raise CmsError("missing signed attribute: signing-certificate")
    if attrs["content_type"][0].native != "data":
        raise CmsError("unexpected content type")

    if attrs["message_digest"][0].native != hashlib.new(hash_alg, content).digest():
        raise CmsError("the signature does not cover this statement")

    # The signing-certificate attribute pins which certificate made the signature.
    if "signing_certificate_v2" in attrs:
        cert_ids = attrs["signing_certificate_v2"][0]["certs"]
        if len(cert_ids) < 1:
            raise CmsError("empty signing-certificate attribute")
        id_alg = cert_ids[0]["hash_algorithm"]["algorithm"].native
        if id_alg not in _HASHES:
            raise CmsError("signing-certificate hash algorithm is not accepted")
        expected = cert_ids[0]["cert_hash"].native
    else:
        cert_ids = attrs["signing_certificate"][0]["certs"]
        if len(cert_ids) < 1:
            raise CmsError("empty signing-certificate attribute")
        id_alg = "sha1"  # identification only; the signature and certificate path carry the security
        expected = cert_ids[0]["cert_hash"].native
    if expected != hashlib.new(id_alg, signer_cert.dump()).digest():
        raise CmsError("signing-certificate attribute does not match the signer certificate")

    # The signature covers the DER of the signed attributes encoded as a universal SET.
    to_verify = signer_info["signed_attrs"].untag().dump()
    signature = signer_info["signature"].native
    public_key = _public_key(signer_cert)
    hash_cls = _HASHES[hash_alg]()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size < MIN_RSA_BITS:
                raise CmsError("RSA key is too small")
            public_key.verify(signature, to_verify, padding.PKCS1v15(), hash_cls)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, to_verify, ec.ECDSA(hash_cls))
        else:
            raise CmsError("unsupported public key type")
    except InvalidSignature:
        raise CmsError("signature verification failed") from None

    signing_time = attrs["signing_time"][0].native if "signing_time" in attrs else None
    return ParsedCades(
        signer_cert=signer_cert,
        other_certs=[c for c in certs if c is not signer_cert],
        hash_alg=hash_alg,
        signing_time=signing_time,
        signed_attrs={k: v for k, v in attrs.items()},
    )
