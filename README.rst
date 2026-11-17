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


Custom Attributes
-----------------

Custom attribute payloads can be interpreted statically, without loading the
assembly or instantiating the attribute class.  The decoder reads the
constructor signature from the ``MemberRef``/``MethodDef`` ``Signature`` blob,
then parses the fixed and named arguments from the raw ``CustomAttribute.Value``
blob:

.. code-block:: python

    import dnfile
    from dnfile import customattr

    pe = dnfile.dnPE(FILEPATH)
    tables = pe.net.mdtables

    result = customattr.decode_custom_attribute(tables.CustomAttribute[0], tables)
    print(customattr.format_interpretation(result))

Every value records the signature evidence it came from in ``argument.basis``.
Unresolved constructors, external enum types, recursive types, unknown element
types, and extra payload bytes are reported as indeterminate rather than being
filled in with default values.  ``result.provenance`` documents that no
assembly was loaded, no attribute was instantiated, and no analyzed file was
imported or executed.

Supported argument types are booleans, chars, the signed/unsigned integer
types, single/double, strings, ``System.Type`` names, ``object`` (boxed
primitive), enums whose underlying type is declared locally, and
single-dimensional arrays of those types.

Example: ``python examples/customattr.py tests/data/hello-world/hello-world.exe``

TODO
----

* more tests
* Documentation on readthedocs


Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
