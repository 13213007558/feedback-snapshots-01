## Development

### Async and non-async

A forked version of [Unasync](https://unasync.readthedocs.io/en/latest/index.html) is used to generate non-async code based on the async implementation. Only make changes to files in `src/cerbos/sdk/_async`. Then run `./pw generate` to re-generate the code in `src/cerbos/sdk/_sync`.

The optional shadow-check package in `src/cerbos/sdk/shadow` lives outside the `_async`/`_sync` tree the generator globs, so its `_async.py` and `_sync.py` clients are maintained in parallel by hand. Keep the two clients' public behaviour in sync when changing either.

The shadow tests under `tests/_shadow` use an in-memory engine and need neither Docker nor `testcontainers`. Run them in isolation with:

```shell
python -m pytest tests/_shadow
```


### Package management

This project uses [PDM](https://pdm.fming.dev) with [Pyprojectx](https://pyprojectx.github.io) for package management. The `pw` script should be used when working with this project.

Adding a new dependency

```shell
./pw pdm add dataclasses-json
```

Adding a tool

```shell
# Add Ruff to tool group
./pw pdm add -dG tools ruff
```

Formatting code

```shell
./pw format
```

Running tests

```shell
./pw test
```

Running a REPL

```shell
./pw pdm run python
```

### Testing with Podman

```shell
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="unix://${XDG_RUNTIME_DIR}/podman/podman.sock" TESTCONTAINERS_RYUK_DISABLED=true ./pw test
```

### Releases

- Run `./pw bump_version PATCH` to generate the changelog and bump the version. (Replace `PATCH` with `MINOR` if you are incrementing the minor version.)
- Commit the changes, tag, and push the new tag to GitHub to launch the CI release job

#### Publishing to Test PyPI

```shell
./pw pdm build

# Test PyPI
./pw twine upload -r testpypi dist/*
```
