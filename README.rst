======
dnfile
======


.. image:: https://github.com/malwarefrank/dnfile/actions/workflows/lint.yml/badge.svg
        :target: https://github.com/malwarefrank/dnfile/actions/workflows/lint.yml
.. image:: https://img.shields.io/pypi/v/dnfile.svg
        :target: https://pypi.python.org/pypi/dnfile
.. image:: https://img.shields.io/pypi/dm/dnfile
        :target: https://pypistats.org/packages/dnfile


Parse .NET executable files.


* Free software: MIT license


Features
--------

* Parse as much as we can, even if the file is partially malformed.
* Easy to use.  Developed with IDE autocompletion in mind.


Quick Start
-----------

.. code-block:: shell

   pip install dnfile

Then create a simple program that loads a .NET binary, parses it, and displays
information about the streams and Metadata Tables.

.. code-block:: python

   import sys
   import dnfile

   filepath = sys.argv[1]

   pe = dnfile.dnPE(filepath)
   pe.print_info()


Everything is an object, and raw structure values are stored in an object's "struct"
attribute.  The CLR directory entry object is accessible from the "net"
attribute of a dnPE object.

.. code-block:: python

    import dnfile
    import hashlib

    pe = dnfile.dnPE(FILEPATH)

    # access the directory entry raw structure values
    pe.net.struct

    # access the metadata raw structure values
    pe.net.metadata.struct

    # access the streams
    for s in pe.net.metadata.streams_list:
        if isinstance(s, dnfile.stream.MetaDataTables):
            # how many Metadata tables are defined in the binary?
            num_of_tables = len(s.tables_list)

    # the last Metadata tables stream can also be accessed by a shortcut
    num_of_tables = len(pe.net.mdtables.tables_list)

    # create a set to hold the hashes of all resources
    res_hash = set()
    # access the resources
    for r in pe.net.resources:
        # if resource data is a simple byte stream
        if isinstance(r.data, bytes):
            # hash it and add the hash to the set
            res_hash.add(hashlib.sha256(r.data).hexdigest())
        # if resource data is a ResourceSet, a dotnet-specific datatype
        elif isinstance(r.data, dnfile.resource.ResourceSet):
            # if there are no entries
            if not r.data.entries:
                # skip it
                continue
            # for each entry in the ResourceSet
            for entry in r.data.entries:
                # if it has data
                if entry.data:
                    # hash it and add the hash to the set
                    res_hash.add(hashlib.sha256(entry.data).hexdigest())




Metadata identity comparison
----------------------------

Metadata rows can be renumbered without changing a program's meaning.  Comparing
raw metadata tokens therefore reports many false changes.  The ``dnfile.identity``
module compares parsed identity instead:

* a type is identified by its namespace, full nesting chain, and generic
  parameters;
* a method is identified by its owning type, name, and structured signature, so
  same-name overloads never merge;
* a signature's embedded ``TypeDefOrRef`` tokens are resolved to the referenced
  type's identity before comparison.

Only a unique one-to-one semantic match is reported as confirmed.  Rows that
have more than one plausible partner are listed separately as ambiguous
candidates.  Every result keeps the original token, table, row number, file
offset, and SHA-256 of both inputs.  Inputs are parsed read-only; no assembly is
loaded or executed.

.. code-block:: python

    import dnfile.identity

    result = dnfile.identity.compare("original.exe", "modified.exe")
    print(result.render())          # investigator-facing text
    payload = result.to_dict()      # the same data as JSON-serializable dicts

    for mapping in result.method_changes:
        print(mapping.left.label(), "->", mapping.right.label())
        print(mapping.left.provenance())

A small command-line wrapper is included:

.. code-block:: shell

    python examples/dnidentity.py original.exe modified.exe
    python examples/dnidentity.py original.exe modified.exe --json

The command exits non-zero when the comparison is not clean.

TODO
----

* more tests
* Documentation on readthedocs


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
