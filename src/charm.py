#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk
"""This is a docstring."""
# TODO: BlockedStatus is never set from the charm code https://juju.is/docs/sdk/constructs#heading--statuses
import logging
from os import environ, path, remove
from os.path import exists
from re import compile, fullmatch
from secrets import token_urlsafe
from subprocess import CalledProcessError, check_call
from typing import TypedDict
from urllib.parse import urlparse

import pem
from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateCreationRequestEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV2,
)
from cryptography import x509
from ops.charm import ActionEvent, CharmBase, ConfigChangedEvent, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

KNOWN_CAS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
    "buypass": "https://api.buypass.com/acme/directory",
    "buypass_test": "https://api.test4.buypass.no/acme/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "sslcom_rsa": "https://acme.ssl.com/sslcom-dv-rsa",
    "sslcom_ecc": "https://acme.ssl.com/sslcom-dv-ecc",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
    "googletest": "https://dv.acme-v02.test-api.pki.goog/directory",
}


class NewCertificateResponse(TypedDict):
    """Typed dict for return from issuing a new certificate."""

    certificate: str
    ca: str
    fullchain: list[str]


class AcmeshOperatorCharm(CharmBase):
    """Charm the service."""

    TEMPORARY_DIR_PATH = "/tmp"
    HTTPPORT = "80"  # Httpport for acme.sh standalone server
    _ACMESH_INSTALL_DIR = environ.get("JUJU_CHARM_DIR")

    def __init__(self, *args):
        super().__init__(*args)
        self.signed_certificates = TLSCertificatesProvidesV2(self, "signed-certificates")
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
        self.framework.observe(
            self.on.create_certificate_action, self._on_create_certificate_action
        )
        self.framework.observe(self.on.renew_certificate_action, self._on_renew_certificate_action)
        self.framework.observe(
            self.on.revoke_certificate_action, self._on_revoke_certificate_action
        )

    def _on_install(self, event: InstallEvent) -> None:
        logger.info("Installing acme.sh")
        self.unit.status = MaintenanceStatus("Installing acme.sh")
        try:
            self._install_acmesh()
            self.unit.status = ActiveStatus()
        except CalledProcessError as e:
            logger.error(f"Could not install acme.sh Error: {e}")
            self.unit.status = BlockedStatus(
                "Could not install acme.sh. Try redeploy or manual installation."
            )

    def _install_acmesh(self) -> None:
        """Install acme.sh and required dependencies."""
        check_call(["apt", "install", "curl", "socat", "git", "-y"])
        check_call(
            ["git", "clone", "--depth", "1", "https://github.com/acmesh-official/acme.sh.git"],
            cwd=self.acmesh_install_dir,
        )
        check_call(
            [
                self.acmesh_install_script,
                "--install",
                "--home",
                self.acmesh_home,
                "--config-home",
                self.acmesh_config_home,
                "--cert-home",
                self.acmesh_home,
            ],
            cwd=self.acmesh_source_dir,
        )

    def _on_config_changed(self, event: ConfigChangedEvent):
        """Handle changed configuration.

        Learn more about config at https://juju.is/docs/sdk/config
        """
        # Fetch the new config value
        try:
            self._validate_use_email()
            logger.debug("use-email updated")
            self._validate_email()
            logger.debug("email updated")
            self._validate_server(server=self.model.config["server"].lower())
            logger.debug("server updated")
            self._validate_eab_kid(
                eab_kid=self.model.config["eab-kid"],
                eab_hmac_key=self.model.config["eab-hmac-key"],
            )
            logger.debug("eab-kid updated")
            self._validate_eab_hmac_key(
                eab_hmac_key=self.model.config["eab-hmac-key"],
                eab_kid=self.model.config["eab-kid"],
            )
            logger.debug("eab-hmac-key updated")
            self._validate_debug(self.model.config["debug"])
            logger.debug("debug updated")
            self._validate_debug_level(self.model.config["debug-level"])
            logger.debug("debug-level updated")
            self.unit.status = ActiveStatus()
        except ValueError as error:
            logger.error(error)
            self.unit.status = BlockedStatus(str(error))

    def _validate_use_email(self) -> bool:
        """Validate the use-email config option."""
        use_email: bool = self.model.config["use-email"]
        return use_email

    def _validate_email(self) -> str:
        """Validate the email address.

        If the user has set use_email to true then validate the email. Otherwise return an empty email.
        """
        email = self.model.config["email"].lower()
        if self.use_email:
            if not email:
                raise ValueError("Email cannot be empty when use-email is true")
            regex = compile(r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")
            if not fullmatch(regex, email):
                raise ValueError(f"Please check email format. Invalid email: {email}")
            return email
        else:
            return ""

    def _validate_server(self, server: str) -> str:
        """Validate the server."""
        if not server:
            raise ValueError("Server cannot be empty")
        if server in KNOWN_CAS.keys():
            server_url = KNOWN_CAS[server]
            self._validate_server_credentials(server_url)
            return server_url
        parse_result = urlparse(server)
        # Check that there is a valid scheme and domain
        if not all([parse_result.scheme, parse_result.netloc]):
            raise ValueError("Server url malformed")
        if parse_result.scheme != "https":
            raise ValueError("Server needs to be secured with https")
        self._validate_server_credentials(server)
        return server

    def _validate_server_credentials(self, server_url: str) -> str:
        """Validate that there are credentials if the server requires it for registration."""
        if "pki.goog" in server_url or "sslcom-dv" in server_url:
            if not self.eab_kid or not self.eab_hmac_key or not self.email:
                raise ValueError(
                    f"email, eab-kid and eab-hmac-key required for using: {server_url}."
                )
        if "zerossl" in server_url:
            if not self.eab_kid or not self.eab_hmac_key:
                if not self.email:
                    raise ValueError("email and/or EAB credentials required for zerossl account.")
        if "buypass" in server_url:
            if not self.email:
                raise ValueError("Email is required for account registration with buypass.")

    def _validate_eab_kid(self, eab_kid: str, eab_hmac_key: str) -> str:
        """Validate the eab kid."""
        if eab_kid and not eab_hmac_key:
            raise ValueError("eab-hmac-key cannot be empty if eab-kid has a value")
        return eab_kid

    def _validate_eab_hmac_key(self, eab_hmac_key: str, eab_kid: str) -> str:
        if eab_hmac_key and not eab_kid:
            raise ValueError("eab-kid cannot be empty if eab-hmac-key has a value")
        return eab_hmac_key

    def _validate_debug(self, debug) -> bool:
        """Validate the debug option."""
        return debug

    def _validate_debug_level(self, debug_level) -> str:
        """Validate the debug levels."""
        valid_levels = ["0", "1", "2", "3"]
        if debug_level not in valid_levels:
            raise ValueError(f"Valid debug levels are: {valid_levels}")
        return debug_level

    def _register_account(self, email: str, server: str) -> None:
        """Register account with the specified server.

        If there is already a registered account for the server there will not be an
        error but if the email has changed then it will be updated.
        """
        try:
            logger.info("registering account")
            if "zerossl" in server:
                if self.eab_kid and self.eab_hmac_key and self.email:
                    commands = self._register_account_with_email_and_credentials_commands(
                        self.email, self.eab_kid, self.eab_hmac_key, self.server
                    )
                    check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
                else:
                    commands = self._register_account_with_credentials_only_commands(
                        self.eab_kid, self.eab_hmac_key, self.server
                    )
                    check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
            elif "pki.goog" in server or "sslcom-dv" in server:
                commands = self._register_account_with_email_and_credentials_commands(
                    self.email, self.eab_kid, self.eab_hmac_key, self.server
                )
                check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
                # Also register ECDSA account for ssl.com
                if "sslcom-dv" in server:
                    commands.append("--ecc")
                    check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
            elif "letsencrypt" in server or "buypass" in server:
                commands = self._register_account_with_email_only_commands(self.email, self.server)
                check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
            else:
                # Attempt to register account using credentials and email if they exist
                # otherwise only register with email
                if self.eab_kid and self.eab_hmac_key and self.email:
                    commands = self._register_account_with_email_and_credentials_commands(
                        self.email, self.eab_kid, self.eab_hmac_key, self.server
                    )
                    check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
                if self.eab_kid and self.eab_hmac_key and not self.email:
                    commands = self._register_account_with_credentials_only_commands(
                        self.eab_kid, self.eab_hmac_key, self.server
                    )
                    check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
                else:
                    commands = self._register_account_with_email_only_commands(
                        self.email, self.server
                    )
                    check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
        except CalledProcessError as e:
            logger.error(e)
            self.unit.status = BlockedStatus(f"Could not register account. Error: {e}")
            raise e

    def _register_account_with_email_only_commands(self, email: str, server: str) -> list[str]:
        """Commands to register an account only using an email. The email can be empty."""
        commands = [
            self.acmesh_script,
            "--register-account",
            "-m",
            email,
            "--server",
            server,
        ]
        return commands

    def _register_account_with_credentials_only_commands(
        self, eab_kid: str, eab_hmac_key: str, server: str
    ) -> list[str]:
        """Commands to register an account with EAB credentials only."""
        commands = [
            self.acmesh_script,
            "--register-account",
            "--eab-kid",
            eab_kid,
            "--eab-hmac-key",
            eab_hmac_key,
            "--server",
            server,
        ]
        return commands

    def _register_account_with_email_and_credentials_commands(
        self, email: str, eab_kid: str, eab_hmac_key: str, server: str
    ) -> list[str]:
        """Commands to register an account with email and EAB credentials."""
        commands = [
            self.acmesh_script,
            "--register-account",
            "-m",
            email,
            "--server",
            server,
            "--eab-kid",
            eab_kid,
            "--eab-hmac-key",
            eab_hmac_key,
        ]
        return commands

    def _should_register_account(self, email: str, server: str) -> bool:
        """Check if an account should be registered or not for the provided server."""
        # Assume that there is an email configured as that is being checked in config validation
        # Does the server have an active account?
        account_info = self._get_account_info_by_server(server=server)
        logger.info(f"account_info: {account_info}")
        if not account_info:
            # Should register a new account with the email on server
            return True
        # We have an account, does it already have the provided email registered?
        mail_string = f"mailto:{email}"
        if mail_string in account_info:
            # There is already an account for the server with the provided email. Skip registration.
            return False
        # We have an account but without an email or another email address.
        # Register the account to update
        return True

    def _get_account_info_by_server(self, server: str) -> str | None:
        """List accounts created by acme.sh.

        Accounts are under the <acme-home-dir>/ca/<server-domain>/

        The "ca" directory only exists if at least one accunt has been registered
        There can be 1 No account, 2 An account with email, 3 An account without email
        """
        account_info_path = self._get_account_info_path(server=server)
        if not exists(account_info_path):
            return None
        account_info: str | None = None
        with open(account_info_path, "r") as account_info_file:
            account_info = account_info_file.read()
        return account_info

    def _get_account_info_path(self, server: str) -> str:
        server_url = urlparse(server)
        # Remove port as acme.sh does not seam to handle this.
        netloc_no_port = server_url.netloc.split(":")[0]
        return path.join(
            self.acmesh_home,
            "ca",
            netloc_no_port,
            server_url.path.removeprefix("/"),
            "account.json",
        )

    def _domain_from_csr(self, csr: str) -> str:
        """Get the domain from a csr."""
        # try:
        try:
            csr_x509 = x509.load_pem_x509_csr(csr.encode())
        except ValueError as e:
            logger.error(f"{e}")
            self.unit.status = BlockedStatus("csr is malformed")
            raise e
        name_attributes = csr_x509.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        common_name = ""
        if len(name_attributes) > 0:
            # The value of the attribute. This will generally be a str, the only times it can be a bytes is when oid is X500_UNIQUE_IDENTIFIER.
            common_name: str = name_attributes[0].value
        # Get the sans
        san_extension = None
        try:
            san_extension = csr_x509.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            logger.error("No sans in csr")
        if san_extension:
            # Get the domain from sans. If the common name is in sans. Prefer that domain name otherwise use the sans dns
            sans_dns = san_extension.value.get_values_for_type(x509.DNSName)
            if common_name in sans_dns:
                domain = common_name
            else:
                domain = sans_dns[0]
        else:
            domain = common_name
        if not domain:
            self.unit.status = BlockedStatus("Domain cannot be empty")
            raise ValueError("Domain cannot be empty")
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
            commands = [
                self.acmesh_script,
                "--signcsr",
                "--csr",
                csr_file_path,
                "--standalone",
                "--httpport",
                self.HTTPPORT,
                "--server",
                self.server,
                "--force",
            ]
            check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
        except CalledProcessError as e:
            logger.error(e)
            logger.error(e.output)
            self.unit.status = BlockedStatus("Could not get certificate from csr")
            raise e
        finally:
            if exists(csr_file_path):
                remove(csr_file_path)

    def _certificates_to_list(self, certificates: str) -> list[str]:
        """Turn a file with many certificates into separate certificates as a list of strings."""
        certs = pem.parse(certificates)
        certs_list = []
        for cert in certs:
            certs_list.append(str(cert))
        return certs_list

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
            commands = [
                self.acmesh_script,
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
            check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)
            with open(crt_file_path, "r") as crt_file:
                certificate = crt_file.read()
                with open(fullchain_file_path, "r") as fullchain_file:
                    fullchain = fullchain_file.read()
                    fullchain_list = self._certificates_to_list(certificates=fullchain)
                    with open(ca_file_path, "r") as ca_file:
                        ca = ca_file.read()
                        response["certificate"] = certificate
                        response["ca"] = ca
                        response["fullchain"] = fullchain_list
            return response
        except CalledProcessError as e:
            logger.error(e)
            self.unit.status = BlockedStatus("Could not issue signed certificate from csr")
            # Do not raise error as that is not recommended in charm relation events
            raise e
        finally:
            # TODO: Should these files be saved???
            file_paths_to_remove = [crt_file_path, fullchain_file_path, ca_file_path]
            for path_to_remove in file_paths_to_remove:
                if exists(path_to_remove):
                    remove(path_to_remove)

    def _on_signed_certificate_creation_request(
        self, event: CertificateCreationRequestEvent
    ) -> None:
        """Attempt to create a signed certificate for the requirer charm."""
        try:
            if self._should_register_account(email=self.email, server=self.server):
                self._register_account(email=self.email, server=self.server)
            csr = event.certificate_signing_request
            new_certificate_response = self._issue_certificate_from_csr(csr=csr)
            self.signed_certificates.set_relation_certificate(
                certificate=new_certificate_response["certificate"],
                certificate_signing_request=csr,
                ca=new_certificate_response["ca"],
                chain=new_certificate_response["fullchain"],
                relation_id=event.relation_id,
            )
            self.unit.status = ActiveStatus("Certificate created.")
            # From what I understand relation hooks are not allowed to fail so catching all errors here
        except Exception as e:
            logger.error(f"Signed certificate creation request error: {e}")

    def _revoke_certificate_by_domain(self, domain: str) -> None:
        """Revoke a certificate based on the domain name."""
        commands = [self.acmesh_script, "--revoke", "-d", domain]
        check_call(self.acmesh_command_wrapper(commands), cwd=self.acmesh_home)

    def _revoke_certificate(self, csr: str, certificate: str) -> None:
        """Revoke a certificate."""
        try:
            domain = self._domain_from_csr(csr)
            self._revoke_certificate_by_domain(domain)
            self.signed_certificates.remove_certificate(certificate)
        except CalledProcessError as e:
            logger.error(e)
            self.unit.status = BlockedStatus("Could not revoke certificate")
            raise e

    def _on_signed_certificate_revocation_request(
        self, event: CertificateRevocationRequestEvent
    ) -> None:
        """Revoke the certificate linked to the csr."""
        try:
            self._revoke_certificate(
                csr=event.certificate_signing_request, certificate=event.certificate
            )
            self.unit.status = ActiveStatus()
        except CalledProcessError as e:
            logger.error(e)

    def _create_certificate_in_action(self, event: ActionEvent) -> None:
        """Attempt to create the certificate and set the results."""
        csr: str = event.params["csr"]
        event.log("Attempting to create new certificate from csr...")
        response: NewCertificateResponse = self._issue_certificate_from_csr(csr)
        event.log("...new certificate created!")
        event.set_results(response)

    def _on_create_certificate_action(self, event: ActionEvent) -> None:
        """### Create at certificate from a csr or domain.

        Currently only from csr is supported.
        """
        try:
            self._create_certificate_in_action(event)
        except CalledProcessError as e:
            event.fail(f"Failed to create new certificate from csr. Error: {e}")

    def _on_revoke_certificate_action(self, event: ActionEvent) -> None:
        """Handle when an admin revokes a certificate."""
        domain = event.params["domain"]
        try:
            event.log(f"Revoking certificate for {domain} ...")
            self._revoke_certificate_by_domain(domain)
            event.log("...certificate revoked.")
            event.set_results({"result": f"Revoked certificate for {domain}"})
        except CalledProcessError as e:
            logger.error(e)
            event.fail(f"Failed to revoke certificate for {domain}. Error: {e}")

    def _on_renew_certificate_action(self, event: ActionEvent) -> None:
        """Renew certificate from csr.

        This function mimics the behaviour of tls-certificates interface. Meaning it will first
        revoke the certificate and then create a new one. This is done so that testing
        is easier. It is a separate operation from
        how the tls-certificates lib handles it as that requires a relation between two charms.
        """
        csr: str = event.params["csr"]
        try:
            domain = self._domain_from_csr(csr)
            event.log(f"Revoking certificate for domain: {domain} ...")
            self._revoke_certificate_by_domain(domain)
            event.log(f"...certificate revoked for domain: {domain}")
            self._create_certificate_in_action(event)
        except ValueError as e:
            logger.error(e)
            event.fail(f"Could not renew certificate. Error: {e}")
        except CalledProcessError as e:
            logger.error(e)
            event.fail(f"Could not renew certificate for domain: {domain} Error: {e}")

    @property
    def acmesh_install_dir(self) -> str:
        """Absolute path to acme.sh install/git clone dir."""
        return self._ACMESH_INSTALL_DIR

    @property
    def acmesh_source_dir(self) -> str:
        """Absolute path to the acme.sh source dir."""
        return path.join(self.acmesh_install_dir, "acme.sh")

    @property
    def acmesh_install_script(self) -> str:
        """Absolute path to the acme.sh install script."""
        return path.join(self.acmesh_install_dir, "acme.sh", "acme.sh")

    @property
    def acmesh_script_path(self) -> str:
        """Absolute path to the acme.sh script."""
        return path.join(self.acmesh_home, "acme.sh")

    @property
    def acmesh_script(self) -> list[str]:
        """The acme.sh script to run in commands."""
        return [
            self.acmesh_script_path,
            "--home",
            self.acmesh_home,
            "--config-home",
            self.acmesh_config_home,
        ]

    @property
    def acmesh_home(self) -> str:
        """Absolute path to the acme home dir."""
        # Using the default /root/.acme.sh for now.
        return "/root/.acme.sh"

    @property
    def acmesh_config_home(self) -> str:
        """Absolute path to the config home.

        For now same as the acmesh_home
        """
        return self.acmesh_home

    @property
    def use_email(self) -> bool:
        """Use an email for account registration config value."""
        return self.model.config["use-email"]

    @property
    def email(self) -> str:
        """Configured email."""
        return self.model.config["email"]

    @property
    def server(self) -> str:
        """Server url. Not the shortname used by acme.sh."""
        config_server = self.model.config["server"].lower()
        if config_server in KNOWN_CAS.keys():
            return KNOWN_CAS[config_server]

        return config_server

    @property
    def eab_kid(self) -> str:
        """Configured eab-kid."""
        return self.model.config["eab-kid"]

    @property
    def eab_hmac_key(self) -> str:
        """Configured eab-hmac-key."""
        return self.model.config["eab-hmac-key"]

    @property
    def debug(self) -> bool:
        """Configured debugging."""
        return self.model.config["debug"]

    @property
    def debug_level(self) -> str:
        """Configured debug level."""
        return self.model.config["debug-level"]

    @property
    def ingress_address(self) -> str | None:
        """The address other service should use to connect to this unit."""
        binding = self.model.get_binding("juju-info")
        if not binding:
            return None
        ingress_address = binding.network.ingress_address
        if not ingress_address:
            return None
        return str(ingress_address)

    def flatten_list(self, list_to_flatten) -> list[str]:
        """Flatten a list with nested list."""
        flattened = []
        for item in list_to_flatten:
            if isinstance(item, list):
                flattened.extend(self.flatten_list(item))
            else:
                flattened.append(item)
        return flattened

    def acmesh_command_wrapper(self, command_list: list) -> list[str]:
        """Flatten the command list and add debug option if appropriate."""
        if self.debug:
            command_list.append(["--debug", self.debug_level])
        return self.flatten_list(command_list)


if __name__ == "__main__":
    main(AcmeshOperatorCharm)
