# Copyright 2023 Martwall
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest

import ops
import ops.testing
from charm import AcmeshOperatorCharm


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = ops.testing.Harness(AcmeshOperatorCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

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
