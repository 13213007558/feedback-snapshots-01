==================
dnfile - Resources
==================

Here is the high-level design of how to access the .NET resources of a dotnet
file.  Note that dotnet resources are different from the PE rsrc section.

We have tried to remain consistent with ECMA 335 terminology.  For example,
a ResourceSet contains a list() of entries, however we call it a ResourceSet
and *not* a ResourceList.


Quick Start
-----------

.NET resources are parsed and can be accessed through the dnPE.net.resources
list.  Every ManifestResource row produces an item, including external
references and embedded resources whose bytes could not be read.  Each item is
a subclass of ClrResource: InternalResource, FileResource, or AssemblyResource
(with the generic ExternalResource for other Implementation targets).

An item's `origin` says where the ManifestResource row declares the content to
live, and `status` says what this parser actually obtained:

* ``ResourceOrigin.Internal`` / ``ResourceStatus.Extracted``: the bytes are in
  this file and are available in `data`.
* ``ResourceOrigin.File`` and ``ResourceOrigin.Assembly``: the row names
  another file or assembly.  `data` is None, `status` is
  ``ResourceStatus.ExternalMissing``, and the parser does **not** open any file
  on its own.  Call ``set_data()`` with content obtained separately if you want
  to parse it; the origin remains external.
* ``ResourceStatus.Unreadable``: an internal resource was declared but its
  bytes could not be read.  `error` explains why and `data` is None.
* ``ResourceStatus.Partial``: the embedded resource-set bytes were read, but at
  least one entry could not be decoded.

`complete` is only True when content was extracted and fully decoded.  A
display name is not a unique key: a file may declare an embedded and an
external resource with the same name, so filter by `origin`/type when looking
for one.

Each InternalResource has a data member that is either bytes or a ResourceSet.
Every entry in a ResourceSet retains its `name`, `type_name`, raw `type_code`,
its offsets (`offset`, `data_offset`) and a `status`; failures are recorded on
the entry (`error`) and in `resource.data.problems` without preventing later
entries from being read.

.. code-block:: python

    pe = dnfile.dnPE(FILEPATH)

    if pe.net and pe.net.resources:
        print("RESOURCES:")
        for rsrc in pe.net.resources:
            print("    Name:   ", rsrc.name)
            print("    Origin: ", rsrc.origin)
            print("    Status: ", rsrc.status)
            print("    Public: ", rsrc.public)
            print("    Private:", rsrc.private)
            if isinstance(rsrc, dnfile.resource.InternalResource):
                if isinstance(rsrc.data, bytes):
                    print("    Type:   ", "bytes")
                    print("    Length: ", len(rsrc.data))
                elif isinstance(rsrc.data, dnfile.resource.ResourceSet):
                    print("    Type:   ", "resource set")
                    print("    Length: ", rsrc.data.struct.NumberOfResources)
                    print("    Complete:", rsrc.data.complete)
                    if rsrc.data.entries:
                        for entry in rsrc.data.entries:
                            print("    RESOURCE ENTRY:")
                            print("        Name:  ", entry.name)
                            print("        Status:", entry.status)
                            if entry.data:
                                dlen = len(entry.data)
                            else:
                                dlen = 0
                            print("        Length:", dlen)
            else:
                # FileResource / AssemblyResource: declared elsewhere
                print("    Source: ", rsrc.source)
                print("    Error:  ", rsrc.error)


High-level Design
-----------------

According to ECMA 335 the ManifestResource table contains information about the
dotnet resources.  Each table row contains information pointing to either an
external resource, as in another file, or an internal resource contained within
the same file as the ManifestResource table itself.

External resources can either be a raw data file or a resource defined in
another dotnet assembly.

All resources can either be raw data, such as a JPEG, or a resource set.  A
resource set contains a list of resources of various data types or objects.
Each data type is used to read the associated item within the set and
instantiate an object at runtime.


ManifestResource Design
-----------------------

The ManifestResource table contains zero or more objects of type
ManifestResourceRow.

ManifestResourceRow:

* Offset
* Flags
  * mrPublic
  * mrPrivate
* Name
* Implementation or None (means InternalResource)
  * row: FileRow or AssemblyRefRow

According to ECMA-335:

* Offset shall be a valid offset into the target file, starting from the Resource entry in the CLI header
* If the resource is an index into the File table, Offset shall be zero
* If Implementation is null, then Offset shall be a valid offset in the current file, starting from the Resource entry in the CLI header

These table and rows are parsed automatically and populate the
dnPE.net.resources list.


Resource data types
-------------------

class ClrResource(abc.ABC):

* name: str
* public: bool
* private: bool
* origin: ResourceOrigin
* status: ResourceStatus
* data: Optional[bytes | ResourceSet]   # None when content was not obtained
* problems: List[str]
* error: Optional[str]
* extracted: bool
* complete: bool

class ExternalResource(ClrResource):

* origin = ResourceOrigin.External
* metadata: MDTableRow or None
* source: Optional[str]   # name of the referenced file/assembly

class FileResource(ExternalResource):

* origin = ResourceOrigin.File
* metadata: FileRow or None
* file_name: Optional[str]

class AssemblyResource(ExternalResource):

* origin = ResourceOrigin.Assembly
* metadata: AssemblyRefRow or None
* assembly_name: Optional[str]

class InternalResource(ClrResource):

* origin = ResourceOrigin.Internal
* rva
* size
* file_offset

class ResourceSet(object):

* parent: ClrResource
* struct
  * Magic: int
  * NumberOfReaders: int
  * SizeOfReaderTypes: int
  * ReaderTypes: bytes
  * Version: int
  * NumberOfResources: int
  * NumberOfResourceTypes: int
  * DataSectionOffset: int
* entries: List[ResourceEntry]
* resource_types
* problems: List[str]
* complete: bool

ResourceEntry(object):

- struct
  - Type: Optional[int]      # raw type code
  - Hash: Optional[int]
  - NamePtr: Optional[int]
  - DataOffset: Optional[int]
  - Name: Optional[bytes]
- name: Optional[str]
- type_name: Optional[str]
- type_code: Optional[int]
- offset: Optional[int]          # payload offset within the data section
- data_offset: Optional[int]     # absolute offset within the resource set
- data: Optional[bytes]
- value: Optional[Any]
- status: ResourceEntryStatus
- error: Optional[str]
- problems: List[str]
- resource: Optional[ClrResource]  # the resource that declared this entry
