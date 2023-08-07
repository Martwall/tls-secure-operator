# Copyright 2023 Martwall
# See LICENSE file for licensing details.

import logging
import time

from pylxd import Client
from pylxd.models import Instance

logger = logging.getLogger(__name__)


class Lxc:
    def __init__(self, instance_name: str) -> None:
        self.instance_name = instance_name
        self.client = Client()

    def _launch_ubuntu_image(self) -> None:
        instance: Instance = self.client.instances.create(
            {
                "name": self.instance_name,
                "source": {
                    "type": "image",
                    "protocol": "simplestreams",
                    "server": "https://images.linuxcontainers.org",
                    "alias": "ubuntu/jammy/amd64",
                },
            },
            wait=True,
        )
        has_started = False
        sleep_count_max = 20
        sleep_count = 0
        while not has_started and sleep_count < sleep_count_max:
            time.sleep(1)
            sleep_count += 1
            logger.info(instance.status)
            if instance.status == "started":
                has_started = True

    def cleanup(self) -> None:
        time.sleep(1)  # Seems like lxd cannot handle calls that are to close together
        self.instance.stop()

    def initialize(self) -> None:
        if not self.client.instances.exists(self.instance_name):
            self._launch_ubuntu_image()
        self.instance.start()

    @property
    def instance(self) -> Instance:
        inst: Instance = self.client.instances.get(self.instance_name)
        if not inst:
            raise ValueError("No instance found")
        return inst
