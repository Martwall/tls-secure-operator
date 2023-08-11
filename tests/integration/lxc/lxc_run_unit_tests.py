# Copyright 2023 Martwall
# See LICENSE file for licensing details.

from lxc import Lxc

if __name__ == "__main__":
    lxc = Lxc()
    lxc.run_tox()
