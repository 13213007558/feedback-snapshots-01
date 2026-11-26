# Python Client Examples

This directory contains various examples of how to use the Python client.
Please read the description at the top of each example for more information
about what the script does and any prerequisites. Most scripts also include
comments throughout the code.

## Available Examples

- pod_logs.py — basic (blocking) pod log streaming example
- pod_logs_non_blocking.py — non-blocking streaming of pod logs with graceful shutdown
- impersonation_identity.py — offline demo of impersonation bound to one logical
  call across pagination and shared clients (no cluster required)

## Setup

These scripts require Python 2.7 or 3.5+ and the Kubernetes client which can be
installed following the directions
[here](https://github.com/kubernetes-client/python#installation).

## Contributions

If you find a problem please file an
[issue](https://github.com/kubernetes-client/python/issues).


---

## Running Examples Locally

### Prerequisites

- Python 3.8 or newer
- Kubernetes Python client installed:
  ```bash
  pip install kubernetes
