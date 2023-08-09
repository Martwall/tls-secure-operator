# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import json
import logging
import unittest
from os import mkdir
from os.path import exists
from shutil import rmtree
from subprocess import CalledProcessError, check_call
from unittest.mock import MagicMock, patch

import ops
import ops.testing
from charm import AcmeshOperatorCharm

logger = logging.getLogger(__name__)


LXC_TEST_INSTANCE_NAME = "test-acmesh-operator-UStJX1kdja3n0qoRlKWzog"
TEMPORARY_DIR_TEST_PATH = "./tests/unit/tmp-test"


def reinstall_acmesh() -> None:
    try:
        # Uninstall
        check_call(["./acme.sh", "--uninstall"], cwd="/root/.acme.sh")
        check_call(["rm", "-R", "/root/.acme.sh"])
        check_call(
            ["./acme.sh", "--install", "-m", "example_mail@example.com"], cwd="/root/acme.sh"
        )
    except CalledProcessError as e:
        logger.error(e)


def _load_relation_data(raw_relation_data: dict) -> dict:
    """Loads relation data from the relation data bag.

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
        if not exists(TEMPORARY_DIR_TEST_PATH):
            mkdir(TEMPORARY_DIR_TEST_PATH)

    def setUp(self):
        self.harness = ops.testing.Harness(AcmeshOperatorCharm)
        self.harness.set_model_name("testing-acmesh-operator")
        self.relation_name = "signedcertificates"
        self.remote_app = "signed-certs-requirer"
        self.remote_unit_name = "signed-certs-requirer/0"
        self.relation_id = self.harness.add_relation(self.relation_name, self.remote_app)
        self.harness.update_config({"email": "someone@example.com"})
        # Pebble testing server ACME directory url
        self.harness.update_config({"server": "https://localhost:14000/dir"})
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

        self.harness.add_relation_unit(self.relation_id, self.remote_unit_name)
        self.harness.charm.HTTPPORT = "5002"
        # Get a valid csr to use for testing
        with open("/root/server.csr", "r") as csr_file:
            self.valid_csr = csr_file.read()

    def test_config_changed_valid(self):
        # Trigger a config-changed event with an updated value
        self.harness.update_config({"email": "test@example.com"})
        # Check the config change was effective
        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus())

    def test_config_changed_invalid(self):
        # Trigger a config-changed event with an updated value
        self.harness.update_config({"email": ""})
        # Check the charm is in BlockedStatus
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)

    def test_valid_url(self):
        self.harness.update_config({"server": "letsencrypt"})
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)

    def test_invalid_url(self):
        self.harness.update_config({"server": "some://invalid/server"})
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)

    def test_server_validation(self):
        self.assertRaises(ValueError, self.harness.charm._validate_server, "")
        server = self.harness.charm._validate_server(server="zerossl")
        self.assertEqual(server, "zerossl")
        self.assertRaises(ValueError, self.harness.charm._validate_server, "http:/url")
        self.assertRaises(ValueError, self.harness.charm._validate_server, "http://acme.com/dir")
        valid_server = "https://acme.com/dir"
        self.assertEqual(self.harness.charm._validate_server(valid_server), valid_server)

    def test_create_random_file(self):
        file_content = "This is some content"
        file_path = self.harness.charm._temporarily_save_file(
            content=file_content, file_ending="txt"
        )
        with open(file_path) as file:
            content = file.read()
            self.assertEqual(content, file_content)
        self.assertTrue(exists(file_path))

    def test_domain_from_csr(self):
        # The csr is created in lxc container
        csr = ""
        with open("/root/server.csr", "r") as csr_file:
            csr = csr_file.read()
        domain = self.harness.charm._domain_from_csr(csr)
        self.assertEqual(domain, "localhost")

    def test_domain_from_csr_raises_error(self):
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
        crt_response = self.harness.charm._issue_certificate_from_csr(csr=self.valid_csr)
        self.assertGreater(len(crt_response["certificate"]), 0)
        self.assertGreater(len(crt_response["ca"]), 0)
        self.assertGreater(len(crt_response["fullchain"]), 0)
        # TODO: Test raising the error

    # @patch("charm._on_signed_certificate_creation_request")
    def test_signed_certificate_creation_request(self):
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

        with patch.object(
            self.harness.charm, "_on_signed_certificate_creation_request", new_callable=MagicMock
        ) as _on_signed_certificate_creation_request_mock:
            # This should trigger the _on_signed_certificate_creation_request()
            self.harness.update_relation_data(self.relation_id, self.remote_unit_name, key_values)
            _on_signed_certificate_creation_request_mock.assert_called_once()
        # expected_relation_data = {
        #     "certificates": [
        #         {
        #             "certificate": certificate,
        #             "certificate_signing_request": certificate_signing_request,
        #             "ca": ca,
        #             "chain": chain,
        #         }
        #     ]
        # }
        # self.harness.charm.signed_certificates.
        # provider_relation_data = self.harness.get_relation_data(
        #     self.relation_id, self.remote_unit_name
        # )
        # logger.info(provider_relation_data)
        # loaded_relation_data = _load_relation_data(dict(provider_relation_data))
        # logger.info(loaded_relation_data)
        # self.assertGreater(len(loaded_relation_data["certificates"][0]["certificate"]), 0)

    @classmethod
    def cleanup_tmp_dir(cls) -> None:
        if exists(TEMPORARY_DIR_TEST_PATH):
            rmtree(TEMPORARY_DIR_TEST_PATH)
