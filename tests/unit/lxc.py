# Copyright 2023 Martwall
# See LICENSE file for licensing details.

import logging
import os
import time

from pylxd import Client
from pylxd.models import Instance

logger = logging.getLogger(__name__)

LXC_INSTANCE_NAME = "test-invoke-12345679"


# TODO: There is no crontab for root
class Lxc:
    CERTIFICATE_CN = "localhost"
    SOURCE_INSTANCE_MOUNT_PATH = "/root/acmesh-operator"

    def __init__(self, instance_name: str) -> None:
        self.instance_name = instance_name
        self.client = Client()
        self._instance = None

    def _launch_ubuntu_image(self) -> None:
        self.client.instances.create(
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

    def _start_instance(self) -> None:
        if self.instance.status_code == 102:
            self.instance.start(timeout=60, force=True, wait=True)
        network_addresses = self.instance.state().network["eth0"]["addresses"]
        timeout = 10
        time_count = 0
        while len(network_addresses) < 1 and time_count <= timeout:
            time.sleep(1)
            time_count += 1
        if timeout == time_count:
            raise RuntimeError("Could not get network address for lxc instance.")

    def cleanup(self) -> None:
        # time.sleep(1)  # Seems like lxd cannot handle calls that are too close together
        self.instance.stop(timeout=60, wait=True)
        # self._unmount_source_directory()

    def initialize(self, override_install_check=False) -> None:
        if not self.client.instances.exists(self.instance_name):
            self._launch_ubuntu_image()
        self._start_instance()
        self._mount_source_directory()
        self.generate_csr()
        if not override_install_check:
            pebble_exit_code = self.start_pebble()
            if pebble_exit_code:
                self.install_software()
                pebble_exit_code = self.start_pebble()
                if pebble_exit_code:
                    raise RuntimeError(f"Pebble exited with exit code {pebble_exit_code}")
        else:
            self.install_software()
            pebble_exit_code = self.start_pebble()
            if pebble_exit_code:
                raise RuntimeError(f"Pebble exited with exit code {pebble_exit_code}")

    def start_pebble(self) -> int:
        with open(f"{os.getcwd()}/tests/unit/pebble-config.json", "r") as config_file:
            config = config_file.read()
            self.instance.files.put("/root/acmesh-operator-pebble-config.json", data=config)
        result = self.instance.execute(
            ["systemctl", "restart", "pebble.service"],
        )
        logger.info(f"start pebble result exit code: {result.exit_code}")
        logger.info(f"result stdout: {result.stdout}")
        logger.info(f"result stderro: {result.stderr}")
        return result.exit_code

    def install_software(self) -> None:
        commands = [
            ["apt", "update"],
            ["apt", "install", "socat", "curl", "man", "git", "-y"],
            ["apt", "install", "python3-pip", "python3-dev", "python3-venv", "-y"],
            ["apt", "install", "snapd", "-y"],
            ["snap", "install", "go", "--classic"],
            ["git", "clone", "https://github.com/letsencrypt/pebble/"],
            ["git", "clone", "https://github.com/jsha/minica.git"],
            ["git", "clone", "https://github.com/acmesh-official/acme.sh.git"],
        ]
        for command in commands:
            logger.info(f"command: {command}")
            result = self.instance.execute(command)
            logger.info(f"result: {result.exit_code}")
            logger.info(f"stdout: {result.stdout}")
            logger.info(f"stderr: {result.stderr}")

        acmesh_install_result = self.instance.execute(
            ["./acme.sh", "--install", "-m", "my@example.com"], cwd="/root/acme.sh"
        )
        logger.info(f"result: {acmesh_install_result.exit_code}")
        logger.info(f"stdout: {acmesh_install_result.stdout}")
        logger.info(f"stderr: {acmesh_install_result.stderr}")

        pebble_install_result = self.instance.execute(
            ["go", "install", "./cmd/pebble"], cwd="/root/pebble"
        )
        logger.info(f"result: {pebble_install_result.exit_code}")
        logger.info(f"stdout: {pebble_install_result.stdout}")
        logger.info(f"stderr: {pebble_install_result.stderr}")
        # Pebble service

        with open(f"{os.getcwd()}/tests/unit/pebble.service", "r") as systemd_file:
            service = systemd_file.read()
            self.instance.files.put("/etc/systemd/system/pebble.service", data=service, mode=644)
            self.instance.execute(["systemctl", "daemon-reload"])
            self.instance.execute(["systemctl", "enable", "pebble.service"])

        # Minica install new certs
        minica_install_result = self.instance.execute(["go", "install"], cwd="/root/minica")
        logger.info(f"result: {minica_install_result.exit_code}")
        logger.info(f"stdout: {minica_install_result.stdout}")
        logger.info(f"stderr: {minica_install_result.stderr}")
        self.instance.execute(
            [
                "/root/go/bin/minica",
                "-ca-cert",
                "pebble.minica.pem",
                "-ca-key",
                "pebble.minica.key.pem",
                "-domains",
                "localhost,pebble",
                "-ip-addresses",
                "127.0.0.1",
            ],
            cwd="/root/pebble/test/certs",
        )
        # Pebble server certificates
        minica_cert_name = "pebble.minica.pem.crt"
        # TODO check if already exiting in /etc/ca-certificates.conf. Perhaps use Grep and exit code of 0
        install_cert_commands = [
            ["echo", minica_cert_name, ">>", "/etc/ca-certificates.conf"],
            ["cp", "pebble.minica.pem", f"/usr/share/ca-certificates/{minica_cert_name}"],
            ["update-ca-certificates"],
        ]

        for command in install_cert_commands:
            logger.info(f"command: {command}")
            result = self.instance.execute(command, cwd="/root/pebble/test/certs")
            logger.info(f"result: {result.exit_code}")
            logger.info(f"stdout: {result.stdout}")
            logger.info(f"stderr: {result.stderr}")

        self._mount_source_directory()
        # Install tox
        setup_virtual_env_commands = [
            ["python3", "-m", "venv", "venv-remote"],
            ["source", "venv-remote/bin/activate"],
            ["pip", "install", "-r", "requirements.txt"],
            ["pip", "install", "tox"],
        ]

        for command in setup_virtual_env_commands:
            logger.info(f"command: {command}")
            result = self.instance.execute(command, cwd=self.SOURCE_INSTANCE_MOUNT_PATH)
            logger.info(f"result: {result.exit_code}")
            logger.info(f"stdout: {result.stdout}")
            logger.info(f"stderr: {result.stderr}")

    def _mount_source_directory(self) -> None:
        path = self._find_acmesh_operator_dir()
        self.instance.devices = {
            "acmesh-operator": {
                "path": self.SOURCE_INSTANCE_MOUNT_PATH,
                "shift": "True",
                "source": path,
                "type": "disk",
            }
        }
        self.instance.save(wait=True)
        logger.info(self.instance.devices)

    def _unmount_source_directory(self) -> None:
        self.instance.devices = {}
        self.instance.save(wait=True)

    def _find_acmesh_operator_dir(self) -> str:
        path = os.getcwd()
        basename = os.path.basename(path)
        max_traversal = 20
        traversal_steps = 0
        while basename != "acmesh-operator" and traversal_steps < max_traversal:
            traversal_steps += 1
            path = os.path.dirname(path)
            basename = os.path.basename(path)

        return path

    def generate_csr(self) -> str:
        self.instance.execute(
            [
                "openssl",
                "req",
                # "-x509",
                "-newkey",
                "rsa:4096",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-sha512",
                "-days",
                "30",
                "-nodes",
                "-subj",
                f"/C=AU/ST=devState/L=Dev/O=devComp/OU=dev/CN={self.CERTIFICATE_CN}",
                "-addext",
                "subjectAltName = DNS:foo.bar",
            ],
            cwd="/root",
        )
        csr_result = self.instance.execute(["cat", "/root/server.csr"])
        if csr_result.exit_code:
            raise RuntimeError(f"Could not read csr. Error: {csr_result.stderr}")
        return csr_result.stdout

    def run_tox(self) -> None:
        self.instance.execute(
            ["tox", "--conf", f"{self.SOURCE_INSTANCE_MOUNT_PATH}/tox_remote.ini"]
        )

    @property
    def instance(self) -> Instance:
        if not self._instance:
            inst: Instance | None = self.client.instances.get(self.instance_name)
            if not inst:
                raise ValueError(f"No instance found with name {self.instance_name}")
            self._instance = inst

        return self._instance
