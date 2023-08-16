#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.
import logging
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
from ops import ActiveStatus, BlockedStatus, InstallEvent, MaintenanceStatus
from ops.charm import CharmBase, RelationJoinedEvent
from ops.main import main
from ops.model import ModelError

logger = logging.getLogger(__name__)


class DevRequirer(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.signed_certificates = TLSCertificatesRequiresV2(
            self, "signedcertificates", expiry_notification_time=1
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

    def _on_signed_certificates_relation_joined(self, event: RelationJoinedEvent):
        private_key = generate_private_key()
        container_ip = None
        try:
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
            logger.error(f"Hostname: {socket.gethostname()}")
            logger.error(f"THe fqdn is: {socket.getfqdn()}")
            logger.error(f"the domain is {domain}")
            logger.error(f"The container ip is: {container_ip}")
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
            logger.info(f"Signing request: {csr.decode()}")
            self.signed_certificates.request_certificate_creation(csr)
        except ModelError as e:
            logger.error(f"Could not get container ip. Error: {e}")
            self.unit.status = BlockedStatus(str(e))

    def _on_certificate_available(self, event: CertificateAvailableEvent):
        logger.info("ca certificate: %s", event.ca)
        logger.info("certificate: %s", event.certificate)
        logger.info("fullchain: %s", event.chain)
        logger.info("csr: %s", event.certificate_signing_request)
        pass

    def _on_certificate_expiring(self, event: CertificateExpiringEvent):
        logger.info("certificate expired: %s", event.certificate)
        pass

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
