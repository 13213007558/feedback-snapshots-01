"""Root conftest: make the in-repo ``deploy_demo`` package importable.

Running ``python -m pytest`` already puts the repository root on ``sys.path``;
this makes plain ``pytest`` invocation behave the same.
"""
