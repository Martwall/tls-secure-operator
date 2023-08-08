# Copyright 2023 Martwall
# See LICENSE file for licensing details.

from lxc import LXC_INSTANCE_NAME, Lxc

if __name__ == "__main__":
    lxc = Lxc(LXC_INSTANCE_NAME)
    lxc.cleanup()
