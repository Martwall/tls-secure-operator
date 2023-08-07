# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import logging
import unittest
from os import mkdir
from os.path import exists
from shutil import rmtree

import ops
import ops.testing
from charm import AcmeshOperatorCharm
from lxc_setup import Lxc

logger = logging.getLogger(__name__)


LXC_TEST_INSTANCE_NAME = "test-acmesh-operator-UStJX1kdja3n0qoRlKWzog"
TEMPORARY_DIR_TEST_PATH = "./tests/unit/tmp-test"

lxc = Lxc(LXC_TEST_INSTANCE_NAME)

class TestCharm(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.addClassCleanup(cls.cleanup_lxc_instance)
        cls.addClassCleanup(cls.cleanup_tmp_dir)
        if not exists(TEMPORARY_DIR_TEST_PATH):
            mkdir(TEMPORARY_DIR_TEST_PATH)
        lxc.initialize()

    def setUp(self):
        self.harness = ops.testing.Harness(AcmeshOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.harness.charm.TEMPORARY_DIR_PATH = TEMPORARY_DIR_TEST_PATH

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
        csr = lxc.generate_csr()
        self.harness.charm._domain_from_csr(csr)

    @classmethod
    def cleanup_tmp_dir(cls) -> None:
        if exists(TEMPORARY_DIR_TEST_PATH):
            rmtree(TEMPORARY_DIR_TEST_PATH)

    @classmethod
    def cleanup_lxc_instance(cls) -> None:
        lxc.cleanup()
