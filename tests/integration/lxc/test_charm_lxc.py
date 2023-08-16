# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
import logging
import unittest
from os.path import exists
from subprocess import CalledProcessError, check_call

import ops
import ops.testing
from charm import AcmeshOperatorCharm
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


def reinstall_acmesh() -> None:
    try:
        # Uninstall
        if exists("/root/.acme.sh"):
            check_call(["./acme.sh", "--uninstall"], cwd="/root/.acme.sh")
            check_call(["rm", "-R", "/root/.acme.sh"])
        # Install
        if exists("/root/acme.sh"):
            check_call(["./acme.sh", "--install"], cwd="/root/acme.sh")
        else:
            check_call(
                ["git", "clone", "--depth", "1", "https://github.com/acmesh-official/acme.sh.git"],
                cwd="/root",
            )
            check_call(["./acme.sh", "--install"], cwd="/root/acme.sh")

    except CalledProcessError as e:
        logger.error(e)


def uninstall_acmesh() -> None:
    try:
        if exists("/root/.acme.sh"):
            check_call(["./acme.sh", "--uninstall"], cwd="/root/.acme.sh")
            check_call(["rm", "-R", "/root/.acme.sh"])
            check_call(["rm", "-R", "/root/acme.sh"])
    except CalledProcessError as e:
        logger.error(e)


class EventMock:
    def __init__(self, csr: str, relation_id: str):
        self.certificate_signing_request = csr
        self.relation_id = relation_id


def _load_relation_data(raw_relation_data: dict) -> dict:
    """Load relation data from the relation data bag.

    Json loads all data.

    Args:
        raw_relation_data: Relation data from the databag

    Returns:
        dict: Relation data in dict format.
    """
    certificate_data = {}
    for key in raw_relation_data:
        try:
            certificate_data[key] = json.loads(raw_relation_data[key])
        except json.decoder.JSONDecodeError:
            certificate_data[key] = raw_relation_data[key]
    return certificate_data


class TestCharm(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.addClassCleanup(cls.cleanup_tmp_dir)

    def setUp(self):
        self.harness = ops.testing.Harness(AcmeshOperatorCharm)
        self.harness.set_model_name("testing-acmesh-operator")
        self.relation_name = "signedcertificates"
        self.remote_app = "signed-certs-requirer"
        self.remote_unit_name = "signed-certs-requirer/0"
        self.relation_id = self.harness.add_relation(self.relation_name, self.remote_app)
        self.harness.update_config({"use-email": True})
        self.harness.update_config({"email": "someone@example.com"})
        # Pebble testing server ACME directory url
        self.harness.update_config({"server": "https://localhost:14000/dir"})
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.harness.add_relation_unit(self.relation_id, self.remote_unit_name)
        self.harness.charm.HTTPPORT = "5002"
        self.harness.charm._ACMESH_INSTALL_DIR = "/root"
        # Get a valid csr to use for testing
        with open("/root/server.csr", "r") as csr_file:
            self.valid_csr = csr_file.read()
        self.certificate_creation_request_event_mock = EventMock(self.valid_csr, self.relation_id)

    def test_domain_from_csr(self):
        # The csr is created in lxc container
        csr = ""
        with open("/root/server.csr", "r") as csr_file:
            csr = csr_file.read()
        domain = self.harness.charm._domain_from_csr(csr)
        self.assertEqual(domain, "localhost")

    def test_domain_from_csr_raises_error(self):
        reinstall_acmesh()
        self.assertRaises(ValueError, self.harness.charm._domain_from_csr, "invalid csr")

    def test_certificate_from_csr(self):
        reinstall_acmesh()
        self.assertEqual(self.harness.charm._certificate_from_csr(self.valid_csr), None)
        self.assertTrue(exists("/root/.acme.sh/localhost/localhost.cer"))
        self.assertTrue(exists("/root/.acme.sh/localhost/ca.cer"))
        self.assertTrue(exists("/root/.acme.sh/localhost/fullchain.cer"))
        self.assertRaises(
            CalledProcessError, self.harness.charm._certificate_from_csr, "invalid csr"
        )

    def test_issue_certificate_from_csr(self):
        reinstall_acmesh()
        logger.error(f"acme_home path = {self.harness.charm.acmesh_home}")
        logger.error(f"acme_script path = {self.harness.charm.acmesh_script}")
        crt_response = self.harness.charm._issue_certificate_from_csr(csr=self.valid_csr)
        self.assertGreater(len(crt_response["certificate"]), 0)
        self.assertGreater(len(crt_response["ca"]), 0)
        self.assertGreater(len(crt_response["fullchain"]), 0)
        # TODO: Test raising the error

    def test_signed_certificate_creation_request_and_certificate_revocation(self):
        reinstall_acmesh()
        key_values = {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": self.valid_csr,
                    }
                ]
            )
        }
        self.harness.update_relation_data(self.relation_id, self.remote_unit_name, key_values)
        # Certs should now be available. Test revocation
        with open("/root/.acme.sh/localhost/localhost.cer") as certificate_file:
            crt = certificate_file.read()
            self.harness.charm._revoke_certificate(csr=self.valid_csr, certificate=crt)

    def test_signed_certificate_creation_request_and_account_creation(self):
        reinstall_acmesh()
        {
            "certificate_signing_requests": json.dumps(
                [
                    {
                        "certificate_signing_request": self.valid_csr,
                    }
                ]
            )
        }
        self.harness.charm._on_signed_certificate_creation_request(
            self.certificate_creation_request_event_mock
        )

        self.assertEqual(self.harness.model.unit.status, ActiveStatus("Certificate created."))
        # There is a valid email and use-email is true. Check an account was created with email.
        account_info = self.harness.charm._get_account_info_by_server(
            server=self.harness.charm.server
        )
        self.assertIn(self.harness.charm.email, account_info)

        # with patch.object(
        #     self.harness.charm, "_on_signed_certificate_creation_request", new_callable=MagicMock
        # ) as _on_signed_certificate_creation_request_mock:
        #     # This should trigger the _on_signed_certificate_creation_request()
        #     self.harness.update_relation_data(self.relation_id, self.remote_unit_name, key_values)
        #     _on_signed_certificate_creation_request_mock.assert_called_once()

    def test_install_acmesh(self):
        uninstall_acmesh()
        event_mock = {}
        self.harness.charm._on_install(event_mock)
        self.assertTrue(exists(self.harness.charm.acmesh_home))

    @classmethod
    def cleanup_tmp_dir(cls) -> None:
        pass
