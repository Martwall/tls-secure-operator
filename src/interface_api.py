# Copyright 2023 Martwall
# See LICENSE file for licensing details.
"""The acmesh-operator provider interface api."""
from enum import Enum

from pydantic import BaseModel


class CertificateRequestTypeEnum(str, Enum):
    """Types of requests the requirer can send."""

    create = "create"
    renew = "renew"
    revoke = "revoke"


class UnitForCertificateResponse(BaseModel):
    """Identification for the unit that created the certificate."""

    name: str
    ingress_address: str | None


class CertificateRequest(BaseModel):
    """Certificate request."""

    certificate_signing_request: str
    request_type: CertificateRequestTypeEnum


class CertificateCreatedResponse(BaseModel):
    """Response to a certificate request with request type "create"."""

    certificate: str
    ca: str
    fullchain: str
    certificate_signing_request: str
    issued_by: UnitForCertificateResponse


class CertificateRevokedResponse(BaseModel):
    """Response to a certificate request with request type "revoke"."""

    certificate_signing_request: str
    is_revoked: bool
    issued_by: UnitForCertificateResponse
