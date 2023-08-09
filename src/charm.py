#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk
"""This is a docstring."""

import logging
from os import remove
from os.path import exists
from secrets import token_urlsafe
from subprocess import CalledProcessError, check_call, check_output
from typing import TypedDict
from urllib.parse import urlparse

from ops.charm import CharmBase, ConfigChangedEvent, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, ErrorStatus, MaintenanceStatus

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
    ca: str
    fullchain: str


class AcmeshOperatorCharm(CharmBase):
    """Charm the service."""

    TEMPORARY_DIR_PATH = "/tmp"
    HTTPPORT = "88"  # Httpport for acme.sh standalone server
    _ACMESH_PATH = "/root/.acme.sh/acme.sh"

    def __init__(self, *args):
        super().__init__(*args)
        self.signed_certificates = TLSCertificatesProvidesV2(self, "signedcertificates")
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
            event.defer()
            return
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
            self._validate_server(server=self.model.config["server"].lower())
            logger.debug("server updated")
            self.unit.status = ActiveStatus()
        except ValueError as error:
            logger.error(error)
            self.unit.status = BlockedStatus(str(error))

    def _validate_email(self) -> str:
        """Validate the email address."""
        email = self.model.config["email"].lower()
        if not email:
            raise ValueError("Email cannot be empty")
        return email

    def _validate_server(self, server: str) -> str:
        """Validate the server."""
        known_cas = [
            "letsencrypt",
            "letsencrypt_test",
            "buypass",
            "buypass_test",
            "zerossl",
            "sslcom",
            "google",
            "googletest",
        ]
        if not server:
            raise ValueError("Server cannot be empty")
        if server in known_cas:
            return server
        parse_result = urlparse(server)
        # Check that there is a valid scheme and domain
        if not all([parse_result.scheme, parse_result.netloc]):
            raise ValueError("Server url malformed")
        if parse_result.scheme != "https":
            raise ValueError("Server needs to be secured with https")
        return server

    def _domain_from_csr(self, csr: str) -> str:
        domain: str | None = None
        try:
            csr_file_path = self._temporarily_save_file(content=csr, file_ending="csr")
            acme_out = check_output(
                [self.acmesh_path, "--showcsr", "--csr", csr_file_path], text=True
            )

            domain_out = check_output(
                ["awk", 'BEGIN{FS="="} NR==1 { print $2 }'], input=acme_out, text=True
            )
            domain = domain_out.removesuffix("\n")
        except CalledProcessError as e:
            logger.error(e)
        finally:
            if exists(csr_file_path):
                remove(csr_file_path)
        if not domain:
            raise ValueError("Could not get domain from csr")
        return domain

    def _temporarily_save_file(self, content: str, file_ending: str) -> str:
        """Temporarily save a file in /tmp.

        content = content to save in the file
        file_ending = file ending. Will be appended to the randomly generated name.

        Returns: Path to the saved file
        """
        random_file_name = f"{token_urlsafe()}.{file_ending}"
        tmp_file_path = f"{self.TEMPORARY_DIR_PATH}/{random_file_name}"
        with open(tmp_file_path, "w") as tmp_file:
            tmp_file.write(content)
        return tmp_file_path

    def _certificate_from_csr(self, csr: str) -> None:
        """Use acme.sh to get a certificate based on a csr."""
        csr_file_path = self._temporarily_save_file(content=csr, file_ending="csr")
        try:
            check_call(
                [
                    self.acmesh_path,
                    "--signcsr",
                    "--csr",
                    csr_file_path,
                    "--standalone",
                    "--httpport",
                    self.HTTPPORT,
                    "--server",
                    self.model.config["server"].lower(),
                ]
            )
        except CalledProcessError as e:
            logger.error(e)
            if exists(csr_file_path):
                remove(csr_file_path)
            raise e
        finally:
            if exists(csr_file_path):
                remove(csr_file_path)

    def _issue_certificate_from_csr(self, csr: str) -> NewCertificateResponse:
        response: NewCertificateResponse = {"ca": "", "certificate": "", "fullchain": ""}
        crt_file_path = ""
        ca_file_path = ""
        fullchain_file_path = ""
        try:
            domain = self._domain_from_csr(csr)
            self._certificate_from_csr(csr)
            crt_file_path = self._temporarily_save_file(content="", file_ending="crt")
            # This should not be available as the requirer is holding the key
            # key_file_path = f"{csr_dir_path}/{relation.app.name}.key.pem"
            ca_file_path = self._temporarily_save_file(content="", file_ending="ca")
            fullchain_file_path = self._temporarily_save_file(content="", file_ending="fullchain")
            check_call(
                [
                    self.acmesh_path,
                    "--install-cert",
                    "-d",
                    domain,
                    "--cert-file",
                    crt_file_path,
                    "--ca-file",
                    ca_file_path,
                    "--fullchain-file",
                    fullchain_file_path,
                ]
            )
            with open(crt_file_path, "r") as crt_file:
                certificate = crt_file.read()
                with open(fullchain_file_path, "r") as fullchain_file:
                    fullchain = fullchain_file.read()
                    with open(ca_file_path, "r") as ca_file:
                        ca = ca_file.read()
                        response["certificate"] = certificate
                        response["ca"] = ca
                        response["fullchain"] = fullchain
        except CalledProcessError as e:
            logger.error(e)
            self.unit.status = ErrorStatus("Could not sign certificate from csr.")
            raise e
        finally:
            file_paths_to_remove = [crt_file_path, fullchain_file_path, ca_file_path]
            for path_to_remove in file_paths_to_remove:
                if exists(path_to_remove):
                    remove(path_to_remove)
        return response

    def _on_signed_certificate_creation_request(
        self, event: CertificateCreationRequestEvent
    ) -> None:
        csr = event.certificate_signing_request
        new_certificate_response = self._issue_certificate_from_csr(csr=csr)
        self.signed_certificates.set_relation_certificate(
            certificate=new_certificate_response["certificate"],
            certificate_signing_request=csr,
            ca=new_certificate_response["ca"],
            chain="",  # For now, could be read from fullchain cert?
            relation_id=event.relation_id,
        )

    def _revoke_certificate(self, csr: str, certificate: str) -> None:
        """Revoke a certificate."""
        try:
            domain = self._domain_from_csr(csr)
            check_call([self.acmesh_path, "--revoke", "-d", domain])
        except CalledProcessError as e:
            logger.error(e)
            self.unit.status = ErrorStatus("Could not revoke certificate")
        self.signed_certificates.remove_certificate(certificate)

    def _on_signed_certificate_revocation_request(
        self, event: CertificateRevocationRequestEvent
    ) -> None:
        self._revoke_certificate(
            csr=event.certificate_signing_request, certificate=event.certificate
        )

    @property
    def acmesh_path(self) -> str:
        """The path to the acme.sh script."""
        return self._ACMESH_PATH


if __name__ == "__main__":
    main(AcmeshOperatorCharm)
