#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.
import logging
from ops.main import main
from ops.charm import CharmBase, RelationJoinedEvent
from ops.model import ModelError
from ops import BlockedStatus, ActiveStatus, InstallEvent, MaintenanceStatus


from charms.tls_certificates_interface.v2.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateInvalidatedEvent,
    AllCertificatesInvalidatedEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key
)

logger = logging.getLogger(__name__)

class DevRequirer(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.signed_certificates = TLSCertificatesRequiresV2(self, "signedcertificates", expiry_notification_time=1)
        self.framework.observe(
            self.signed_certificates.on.certificate_available,
            self._on_certificate_available
        )
        self.framework.observe(
            self.signed_certificates.on.certificate_expiring,
            self._on_certificate_expiring
        )
        self.framework.observe(
            self.signed_certificates.on.certificate_invalidated,
            self._on_certificate_invalidated
        )
        self.framework.observe(
            self.signed_certificates.on.all_certificates_invalidated,
            self._on_all_certificates_invalidated
        )
        self.framework.observe(
            self.on.signedcertificates_relation_joined,
            self._on_signed_certificates_relation_joined
        )
        self.framework.observe(
            self.on.install,
            self._on_install
        )

    def _on_install(self, event: InstallEvent):
        self.unit.status = MaintenanceStatus("Installing")
        logger.info("Nothing to install")
        self.unit.status = ActiveStatus()
        return

    def _on_signed_certificates_relation_joined(self, event: RelationJoinedEvent):
        private_key = generate_private_key()
        container_ip = None
        try:
            container_ip = str(self.model.get_binding("signedcertificates").network.ingress_address)
            csr = generate_csr(private_key=private_key, subject=container_ip)
            self.signed_certificates.request_certificate_creation(csr)
        except ModelError as e:
            logger.error(f"Could not get container ip. Error: {e}")
            self.unit.status = BlockedStatus(str(e))
        

    def _on_certificate_available(self, event: CertificateAvailableEvent):
        logger.info("ca certificate: ", event.ca)
        logger.info("certificate: ", event.certificate)
        logger.info("fullchain: ", event.chain)
        logger.info("csr: ", event.certificate_signing_request)
        pass

    def _on_certificate_expiring(self, event: CertificateExpiringEvent):
        logger.info("certificate expired: ", event.certificate)
        pass

    def _on_certificate_invalidated(self, event: CertificateInvalidatedEvent):
        logger.info("certificate invalidated: ", event.certificate)
        logger.info("csr: ", event.certificate_signing_request)
        logger.info("chain: ", event.chain)
        logger.info("Reason: ", event.reason)
        pass

    def _on_all_certificates_invalidated(self, event: AllCertificatesInvalidatedEvent):
        logger.info("All certificates invalidated")
        pass
    

if __name__ == "__main__":
    main(DevRequirer)