# Contributing

Contributions are much welcome! If not able to contribute please submit an issue on github.

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

You need to have LXD, JuJu and juju-crashdump installed locally. Install via snap.

You can create an environment for development with `tox`:

```shell
tox devenv -e integration
source venv/bin/activate
```

## Testing

This project uses `tox` for managing test environments. There are some pre-configured environments
that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
tox run -e format           # update your code according to linting rules
tox run -e lint             # code style
tox run -e unit             # unit tests
tox run -e integration      # integration tests on juju, needs "pebble-dev" lxc container
tox run -e integration-lxc  # integration tests on lxc, only testing acme.sh
tox                         # runs 'format', 'lint', and 'unit' environments
```

There is one environment `integration-lxc` that setups up a container using lxd. This container runs a development pebble-server but does not need juju to work. Please note that this mounts the code base inside the container.

A [pebble development server](https://github.com/letsencrypt/pebble) needs to be running in an lxc container named "pebble-dev" in order to run `tox run -e integration`. To see how to set this up use the documentation of the pebble server and also see the [setup file](tests/integration/lxc/lxc.py) for the lxc integration testing.

VS Code is used by the author and hence the .vscode dir with the launch.json file to run the juju integration tests.

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

<!-- You may want to include any contribution/style guidelines in this document>
