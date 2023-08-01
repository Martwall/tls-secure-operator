#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following tutorial that will help you
develop a new k8s charm using the Operator Framework:

https://juju.is/docs/sdk/create-a-minimal-kubernetes-charm
"""

import logging
from os import mkdir
from os.path import exists
from subprocess import CalledProcessError, check_call, check_output
from typing import TypedDict

from ops.charm import CharmBase, ConfigChangedEvent, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ErrorStatus, MaintenanceStatus, Relation

from lib.charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateCreationRequestEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV2,
)

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)


class NewCertificateResponse(TypedDict):
    """Typed dict for return from issuing a new certificate."""

    certificate: str
    fullchain: str


class AcmeshOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.signed_certificates = TLSCertificatesProvidesV2(self, "signedcertificates")
        self.signed_certificates
        self.framework.observe(
            self.signed_certificates.on.certificate_creation_request,
            self._on_signed_certificate_creation_request,
        )
        self.framework.observe(
            self.signed_certificates.on.certificate_revocation_request,
            self._on_signed_certificate_revocation_request,
        )
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_install(self, event: InstallEvent) -> None:
        logger.info("Installing acme.sh")
        self.unit.status = MaintenanceStatus("Installing acme.sh")
        try:
            email = self._validate_email()
            check_call(["apt", "install", "-y", "curl"])
            # required by acme.sh to run standalone
            check_call(["apt", "install", "-y", "socat"])
            check_call(["curl", "https://get.acme.sh", "|", "sh", "-s", f"email={email}"])
        except ValueError as e:
            logger.error(e)
            self.unit.status = BlockedStatus(str(e))
        except CalledProcessError as e:
            logger.error(f"Could not install acme.sh Error code: {e.returncode}")
            self.unit.status = BlockedStatus(
                f"Could not install acme.sh Error: {str(e)} Try redeploy or manual installation"
            )

    def _on_config_changed(self, event: ConfigChangedEvent):
        """Handle changed configuration.

        Learn more about config at https://juju.is/docs/sdk/config
        """
        # Fetch the new config value
        try:
            self._validate_email()
            logger.debug("email updated")
            self.unit.status = ActiveStatus()
        except ValueError as error:
            logger.error(error)
            self.unit.status = BlockedStatus(str(error))

    def _validate_email(self) -> str:
        email = self.model.config["email"].lower()
        if not email:
            raise ValueError("Email cannot be empty")
        return email

    def _issue_certificate_from_csr(self, csr: str, relation: Relation) -> NewCertificateResponse:
        try:
            csr_dir_path = f"/srv/{relation.id}"
            if not exists(csr_dir_path):
                mkdir(csr_dir_path)
            csr_file_path = f"{csr_dir_path}/{relation.app.name}.csr"
            with open(csr_file_path, "w") as csr_file:
                csr_file.write(csr)

            check_call(
                [
                    "acme.sh",
                    "--signcsr",
                    "--csr",
                    csr_file_path,
                    "--standalone",
                    "--httpport",
                    "88",
                ]
            )
            domain = check_output(
                [
                    "acme.sh",
                    "--showcsr",
                    "--csr",
                    csr_file_path,
                    "|",
                    "awk",
                    "'BEGIN{FS='" "=" "'} NR==1 { print $2 }'",
                ]
            )
            cert_file_path = f"{csr_dir_path}/{relation.app.name}.cert.pem"
            # This should not be available
            # key_file_path = f"{csr_dir_path}/{relation.app.name}.key.pem"
            fullchain_file_path = f"{csr_dir_path}/{relation.app.name}.fullchain.pem"
            check_call(
                [
                    "acme.sh",
                    "--install-cert",
                    "-d",
                    domain,
                    "--cert-file",
                    cert_file_path,
                    "--fullchain-file",
                    fullchain_file_path,
                ]
            )
            with open(cert_file_path, "r") as cert_file:
                certificate = cert_file.read()
                with open(fullchain_file_path, "r") as fullchain_file:
                    fullchain = fullchain_file.read()
                    return {"certificate": certificate, "fullchain": fullchain}
        except CalledProcessError as e:
            logger.error(e)
            self.unit.status = ErrorStatus(
                f"Could not sign certificate from csr at path: {csr_file_path}"
            )

    def _on_signed_certificate_creation_request(
        self, event: CertificateCreationRequestEvent
    ) -> None:
        csr = event.certificate_signing_request
        relation = self.model.get_relation(event.relation_id)
        new_certificate_response = self._issue_certificate_from_csr(csr=csr, relation=relation)
        self.signed_certificates.set_relation_certificate(
            certificate=new_certificate_response["certificate"],
            certificate_signing_request=csr,
            ca="",  # For now, could be read from fullchain cert?
            chain="",  # For now, could be read from fullchain cert?
            relation_id=event.relation_id,
        )

    def _on_signed_certificate_revocation_request(
        self, event: CertificateRevocationRequestEvent
    ) -> None:
        pass


if __name__ == "__main__":
    main(AcmeshOperatorCharm)
