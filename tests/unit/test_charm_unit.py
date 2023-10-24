# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing
import logging
import socket
import subprocess
import unittest
from os import mkdir
from os.path import abspath, exists, join
from shutil import rmtree
from unittest.mock import PropertyMock, patch

import ops
import ops.testing
from charm import KNOWN_CAS, TlsSecureOperatorCharm
from charms.tls_certificates_interface.v2.tls_certificates import (
    generate_csr,
    generate_private_key,
)

logger = logging.getLogger(__name__)


LXC_TEST_INSTANCE_NAME = "test-tls-secure-operator-UStJX1kdja3n0qoRlKWzog"
TEMPORARY_DIR_TEST_PATH = "./tests/unit/tmp-test"


class TestCharm(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.addClassCleanup(cls.cleanup_tmp_dir)
        if not exists(TEMPORARY_DIR_TEST_PATH):
            mkdir(TEMPORARY_DIR_TEST_PATH)

    def setUp(self):
        # self.patcher = patch.object(TlsSecureOperatorCharm, "ingress_address", return_value="1.2.3.4")
        # self.mock_ingress_address = MagicMock(spec=TlsSecureOperatorCharm, ingress_address="1.2.3.4")
        self.harness = ops.testing.Harness(TlsSecureOperatorCharm)
        self.harness.set_model_name("testing-tls-secure-operator")
        self.harness.model.unit.name = "tls-secure/0"
        self.relation_name = "signed-certificates"
        self.remote_app = "signed-certs-requirer"
        self.remote_unit_name = "signed-certs-requirer/0"
        self.relation_id = self.harness.add_relation(self.relation_name, self.remote_app)
        self.haproxy_relation_name = "haproxy"
        self.haproxy_remote_app = "haproxy"
        self.haproxy_remote_unit_name = "haproxy/0"
        self.haproxy_relation_id = self.harness.add_relation(
            self.haproxy_relation_name, self.haproxy_remote_app
        )

        self.harness.update_config({"email": "someone@example.com"})
        # Pebble testing server ACME directory url
        self.harness.update_config({"server": "https://localhost:14000/dir"})
        self.addCleanup(self.harness.cleanup)

        self.harness.begin()

        # self.harness.charm.ingress_address = MagicMock()
        self.harness.charm.HAPROXY_SERVICE_OPTIONS_FILE_NAME = join(
            abspath(TEMPORARY_DIR_TEST_PATH), "haproxy_service_options"
        )
        self.harness.charm.HTTPPORT = "5002"
        self.harness.charm._ACMESH_INSTALL_DIR = "/root"
        self.harness.add_relation_unit(self.relation_id, self.remote_unit_name)

    def test_config_changed_valid(self):
        # Trigger a config-changed event with an updated value
        self.harness.update_config({"email": "test@example.com"})
        # Check the config change was effective
        self.assertEqual(self.harness.model.unit.status, ops.ActiveStatus("Config updated."))

    def test_config_changed_invalid(self):
        # Trigger a config-changed event with an updated value
        self.harness.update_config({"email": ""})
        # Check the charm is in BlockedStatus
        self.assertEqual(
            self.harness.model.unit.status,
            ops.BlockedStatus("Email cannot be empty when use-email is true"),
        )

    def test_validate_debug_level(self):
        self.harness.update_config({"debug-level": "INFO"})
        self.assertIsInstance(self.harness.model.unit.status, ops.BlockedStatus)
        self.harness.update_config({"debug-level": "2"})
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)

    def test_config_use_email_in_combination_with_email(self):
        self.harness.update_config({"use-email": False, "email": ""})
        self.assertIsInstance(self.harness.model.unit.status, ops.ActiveStatus)
        self.harness.update_config({"use-email": True, "email": "sdlkfj@gmail"})
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
        self.assertEqual(server, "https://acme.zerossl.com/v2/DV90")
        self.assertRaises(ValueError, self.harness.charm._validate_server, "http:/url")
        self.assertRaises(ValueError, self.harness.charm._validate_server, "http://acme.com/dir")
        valid_server = "https://acme.com/dir"
        self.assertEqual(self.harness.charm._validate_server(valid_server), valid_server)
        # should require eab-kid and eab-hmac-key for some servers

        google_server_url = KNOWN_CAS["google"]
        ssl_com_server_url = KNOWN_CAS["sslcom_rsa"]
        urls_to_validate = [google_server_url, ssl_com_server_url]
        for url in urls_to_validate:
            self.assertRaises(
                ValueError,
                self.harness.charm._validate_server,
                url,
            )
        self.harness.update_config(
            {
                "use-email": True,
                "email": "some_email+tls-secure@example.com",
                "server": "https://dv.acme-v02.api.pki.goog/directory",
                "eab-kid": "some-eab-kid",
                "eab-hmac-key": "some-hmac-key",
            }
        )
        for url in urls_to_validate:
            validated_server = self.harness.charm._validate_server(google_server_url)
            self.assertEqual(validated_server, self.harness.charm.server)

    def test_eab_kid_validation(self):
        eab_kid = "891264iasudfhihu"
        eab_hmac_key = ""
        self.assertRaises(ValueError, self.harness.charm._validate_eab_kid, eab_kid, eab_hmac_key)
        eab_hmac_key = "kjashdkfjhasdkfhuinnnbeuibcIUFDGIIDdjfhsd9879jshd"
        eab_kid_validated = self.harness.charm._validate_eab_kid(eab_kid, eab_hmac_key)
        self.assertEqual(eab_kid, eab_kid_validated)
        self.assertEqual(self.harness.charm._validate_eab_hmac_key("", ""), "")

    def test_eab_hmac_key_validation(self):
        eab_kid = ""
        eab_hmac_key = "kjashdkfjhasdkfhuinnnbeuibcIUFDGIIDdjfhsd9879jshd"
        self.assertRaises(
            ValueError, self.harness.charm._validate_eab_hmac_key, eab_hmac_key, eab_kid
        )
        eab_kid = "891264iasudfhihu"
        eab_hmac_key_validated = self.harness.charm._validate_eab_hmac_key(eab_hmac_key, eab_kid)
        self.assertEqual(eab_hmac_key, eab_hmac_key_validated)
        self.assertEqual(self.harness.charm._validate_eab_hmac_key("", ""), "")

    def test_create_random_file(self):
        file_content = "This is some content"
        file_path = self.harness.charm._temporarily_save_file(
            content=file_content, file_ending="txt"
        )
        with open(file_path) as file:
            content = file.read()
            self.assertEqual(content, file_content)
        self.assertTrue(exists(file_path))

    def test_account_info_path(self):
        server = self.harness.charm.server
        account_info_path = self.harness.charm._get_account_info_path(server=server)
        self.assertEqual(account_info_path, "/root/.acme.sh/ca/localhost/dir/account.json")
        account_info_path = self.harness.charm._get_account_info_path(
            server="https://localhost.com/dir"
        )
        self.assertEqual(account_info_path, "/root/.acme.sh/ca/localhost.com/dir/account.json")

    def test_certificates_to_list(self):
        """Test that a certificate list is generated properly."""
        cert_mock_one_cert = ""
        cert_mock_two_certs = ""
        with open("./tests/unit/mocks/cert_mock_one_cert.pem", "r") as pem_file:
            cert_mock_one_cert = pem_file.read()
        with open("./tests/unit/mocks/cert_mock_two_certs.pem", "r") as pem_file:
            cert_mock_two_certs = pem_file.read()
        one_cert_list = self.harness.charm._certificates_to_list(certificates=cert_mock_one_cert)
        two_certs_list = self.harness.charm._certificates_to_list(certificates=cert_mock_two_certs)
        self.assertEqual(len(one_cert_list), 1)
        self.assertEqual(len(two_certs_list), 2)
        self.assertIsInstance(one_cert_list[0], str)

    def test_domain_from_csr(self):
        hostname = socket.gethostname()
        sans_domain = hostname + ".lxd"
        sans_dns = [sans_domain]
        key = generate_private_key()
        csr = generate_csr(
            key,
            subject="some subject",
            sans_dns=sans_dns,
            sans_ip=["1.1.1.1"],
        )
        domain = self.harness.charm._domain_from_csr(csr.decode())
        self.assertEqual(domain, sans_domain)

    def test_validate_proxy_service(self) -> None:
        """Test the validation of the proxy service."""
        service = "nginx"
        self.assertRaises(ValueError, self.harness.charm._validate_proxy_service, service)
        service = "None"
        self.assertEqual(self.harness.charm._validate_proxy_service(service), "none")
        self.harness.update_config({"proxy-service": "none"})
        self.assertEqual(None, self.harness.charm.proxy_service)

    def test_invalid_haproxy_config(self) -> None:
        """Test that the haproxy config cannot be empty."""
        with self.assertRaises(ValueError) as cm:
            self.harness.charm._validate_haproxy_service_options("")
            logger.error(cm.exception)

    def test_should_update_haproxy_config(self) -> None:
        """Test when the haproxy config should be updated."""
        mock_ingress_address = PropertyMock(return_value="1.2.3.4")
        with patch.object(TlsSecureOperatorCharm, "ingress_address", mock_ingress_address):
            # no relation joined so this should be false
            should_update = self.harness.charm._should_update_haproxy_relation_data()
            self.assertFalse(should_update)
            # now write the file
            self.harness.charm.haproxy_service_options
            should_update = self.harness.charm._should_update_haproxy_relation_data()
            self.assertFalse(should_update)
            self.assertTrue(exists(self.harness.charm.haproxy_service_options_file_path))
            # join the relation, because the config is the same it should not update
            self.harness.add_relation_unit(self.haproxy_relation_id, self.haproxy_remote_unit_name)
            should_update = self.harness.charm._should_update_haproxy_relation_data()
            self.assertFalse(should_update)

    @patch("charm.TlsSecureOperatorCharm._is_proxy_service_up")
    def test_should_wait_for_haproxy_service(self, mock_is_proxy_service_up) -> None:
        """Test when the charm should wait for the proxy relation to be established."""
        testing_proxy_domain = "some-domain"
        # No proxy service configured --> should not wait
        self.harness.update_config({"proxy-service": "none"})
        self.assertEqual(
            self.harness.charm._should_wait_for_proxy_relation(testing_proxy_domain), False
        )

        # Proxy service configured but no proxy relation --> should wait
        self.harness.remove_relation(self.haproxy_relation_id)
        self.harness.update_config({"proxy-service": "haproxy"})
        self.assertEqual(
            self.harness.charm._should_wait_for_proxy_relation(testing_proxy_domain), True
        )
        self.assertIsInstance(self.harness.charm.unit.status, ops.WaitingStatus)

        # Proxy service configured and proxy relation, can reach proxy service --> should not wait
        self.harness.add_relation(self.haproxy_relation_name, self.haproxy_remote_app)
        mock_is_proxy_service_up.return_value = True
        self.assertEqual(
            self.harness.charm._should_wait_for_proxy_relation(testing_proxy_domain), False
        )

        # Proxy service configured and proxy relation, can not reach proxy service --> should wait
        mock_is_proxy_service_up.return_value = False
        self.assertEqual(
            self.harness.charm._should_wait_for_proxy_relation(testing_proxy_domain), True
        )

    @patch("charm.check_call")
    def test_is_proxy_service_up(self, mock_check_call) -> None:
        """Test the check if the proxy service is up."""
        mock_check_call.side_effect = None
        is_up = self.harness.charm._is_proxy_service_up("example_url")
        self.assertTrue(is_up)
        mock_check_call.side_effect = subprocess.CalledProcessError(7, "some command")
        is_up = self.harness.charm._is_proxy_service_up("example_url")
        self.assertFalse(is_up)

    def test_haproxy_relation_joined(self) -> None:
        """Test the haproxy relation joined."""
        # The relation does not exist so update should return false.

    def test_revoke_action(self):
        """Test revoking a certificate via an action."""

    @classmethod
    def cleanup_tmp_dir(cls) -> None:
        if exists(TEMPORARY_DIR_TEST_PATH):
            rmtree(TEMPORARY_DIR_TEST_PATH)
