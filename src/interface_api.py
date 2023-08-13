from enum import Enum
from pydantic import BaseModel

class CertificateRequestTypeEnum(str, Enum):
    create = "create"
    renew = "renew"
    revoke = "revoke"

class Unit(BaseModel):
    name: str
    ingress_address: str

class CertificateRequest(BaseModel):
    certificate_signing_request: str
    request_type: CertificateRequestTypeEnum

class CertificateCreatedResponse(BaseModel):
    certificate: str
    ca: str
    fullchain: str
    certificate_signing_request: str
    issued_by: Unit
