#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.
import logging
import os
import socket

from charms.tls_certificates_interface.v2.tls_certificates import (
    AllCertificatesInvalidatedEvent,
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from cryptography import x509
from ops import ActiveStatus, BlockedStatus, InstallEvent, MaintenanceStatus
from ops.charm import CharmBase, RelationJoinedEvent
from ops.main import main
from ops.model import ModelError

logger = logging.getLogger(__name__)


class DevRequirer(CharmBase):
    CSR_FILE_PATH = os.path.join(os.environ.get("JUJU_CHARM_DIR"), "request.csr")

    def __init__(self, *args):
        super().__init__(*args)
        self.signed_certificates = TLSCertificatesRequiresV2(
            self, "signed-certificates", expiry_notification_time=1
        )
        self.framework.observe(
            self.signed_certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.signed_certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.signed_certificates.on.certificate_invalidated, self._on_certificate_invalidated
        )
        self.framework.observe(
            self.signed_certificates.on.all_certificates_invalidated,
            self._on_all_certificates_invalidated,
        )
        self.framework.observe(
            self.on.signedcertificates_relation_joined,
            self._on_signed_certificates_relation_joined,
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent):
        self.unit.status = MaintenanceStatus("Installing")
        logger.info("Nothing to install")
        self.unit.status = ActiveStatus()
        return

    def _generate_new_csr(self) -> bytes:
        container_ip = None
        try:
            private_key = self._get_private_key()
            hostname = socket.gethostname()
            if not hostname:
                logger.error("No hostname from socket.gethostname()")
                logger.error(f"THe fqdn is: {socket.getfqdn()}")
                hostname = "dev-requirer"
            domain = hostname + ".lxd"
            sans_dns = [domain]
            container_ip = str(
                self.model.get_binding("signedcertificates").network.ingress_address
            )
            logger.info(f"Hostname: {socket.gethostname()}")
            logger.info(f"THe fqdn is: {socket.getfqdn()}")
            logger.info(f"the domain is {domain}")
            logger.info(f"The container ip is: {container_ip}")
            # Acme.sh does not seem to support IP address assignment,
            # perhaps a workaround could be used by filtering and checking
            # the contents of the csr first.
            # if container_ip:
            #     csr = generate_csr(
            #         private_key=private_key,
            #         subject=domain,
            #         sans_ip=[container_ip],
            #         sans_dns=sans_dns,
            #     )
            # else:
            csr = generate_csr(
                private_key=private_key,
                subject=domain,
                sans_dns=sans_dns,
            )
            with open(self.CSR_FILE_PATH, "wb") as csr_file:
                csr_file.write(csr)
            return csr
        except ModelError as e:
            logger.error(f"Could not get container ip. Error: {e}")
            self.unit.status = BlockedStatus(str(e))

    def _get_private_key(self) -> bytes:
        private_key_path = os.path.join(os.environ.get("JUJU_CHARM_DIR"), "key.pem")
        if os.path.exists(private_key_path):
            with open(private_key_path, "rb") as key_file:
                return key_file.read()
        private_key = generate_private_key()
        with open(private_key_path, "wb") as key_file:
            key_file.write(private_key)
        return private_key

    def _on_signed_certificates_relation_joined(self, event: RelationJoinedEvent):
        csr = self._generate_new_csr()
        self.signed_certificates.request_certificate_creation(csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent):
        logger.info("ca certificate: %s", event.ca)
        logger.info("certificate: %s", event.certificate)
        logger.info("fullchain: %s", event.chain)
        logger.info("csr: %s", event.certificate_signing_request)
        try:
            certificate_object = x509.load_pem_x509_certificate(data=event.certificate.encode())
            logger.info(f"Certificate not valid after: {certificate_object.not_valid_after}")
        except ValueError:
            logger.warning("Could not load certificate.")
        # self.renew_certificate()
        # self.revoke_certificate()

    def revoke_certificate(self) -> None:
        with open(self.CSR_FILE_PATH, "rb") as csr_file:
            csr = csr_file.read()
            self.signed_certificates.request_certificate_revocation(csr)

    def renew_certificate(self) -> None:
        old_csr = b""
        with open(self.CSR_FILE_PATH, "rb") as old_csr_file:
            old_csr = old_csr_file.read()
        new_csr = self._generate_new_csr()
        self.signed_certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr, new_certificate_signing_request=new_csr
        )

    def _on_certificate_expiring(self, event: CertificateExpiringEvent):
        logger.info("certificate expired: %s", event.certificate)
        # Get a new certificate
        csr = self._generate_new_csr()
        self.signed_certificates.request_certificate_creation(csr)

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent):
        logger.info("certificate invalidated: %s", event.certificate)
        logger.info("csr: %s", event.certificate_signing_request)
        logger.info("chain: %s", event.chain)
        logger.info("Reason: %s", event.reason)
        pass

    def _on_all_certificates_invalidated(self, event: AllCertificatesInvalidatedEvent):
        logger.info("All certificates invalidated")
        pass


if __name__ == "__main__":
    main(DevRequirer)
