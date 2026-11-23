===============
Schema Packages
===============

The `Registry` object is a useful way to ship Python packages which essentially bundle a set of JSON Schemas for use at runtime from Python.

In order to do so, you likely will want to:

* Collect together the JSON files you wish to ship
* Put them inside a Python package (one you possibly tag with the ``jsonschema`` keyword for easy discoverability).
  Remember to ensure you have configured your build tool to include the JSON files in your built package distribution -- for e.g. :hatch:`hatch </>` this is likely automatic, but for `setuptools <setuptools:index>` may involve creating a suitable :file:`MANIFEST.in`.
* Instantiate a `Registry` object somewhere globally within the package
* Call `Registry.crawl` at import-time, such that users of your package get a "fully ready" registry to use

For an example of such a package, see `jsonschema-specifications <jsonschema-specifications:index>`, which bundles the JSON Schema "official" schemas for use.

Exporting a Standalone Bundle
-----------------------------

A `Registry` which has been populated (e.g. via `Registry.combine` or a retrieval function) may be useful only within the network it can reach.
If you need to hand a subset of its resources to a wholly offline consumer, use `referencing.bundle.bundle` (or `Registry.bundle`) to export only explicitly approved roots and dependencies.

.. code:: python

    from referencing import Registry
    from referencing.bundle import bundle

    shared = Registry(retrieve=...).with_contents(
        [("https://example.com/root", root)],
    )
    package = bundle(
        shared,
        "https://example.com/root",
        allowed={"https://example.com/common"},
    )
    customer_registry = package.registry

Only the given roots, and dependencies listed in ``allowed`` (or approved by a ``deliverable`` callable), are included.
Nested resources with their own identifiers and anchors are included along with the resource which contains them, and ``package.manifest`` explains each root's nested identifiers and anchors.

The resulting registry has no retrieval function, so it cannot silently call back into your network.
If a needed dependency is not exportable, `referencing.exceptions.MissingDependencies` is raised, identifying the missing resource, its category, and the root which needs it.
Pass ``strict=False`` to inspect a `referencing.bundle.Bundle` with its partial contents and ``missing`` entries instead.
