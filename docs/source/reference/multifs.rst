Multi Filesystem
================

A MultiFS is a filesystem composed of a sequence of other filesystems,
where the directory structure of each overlays the previous filesystem
in the sequence.

One use for such a filesystem would be to selectively override a set of
files, to customize behavior. For example, to create a filesystem that
could be used to *theme* a web application. We start with the following
directories::


    `-- templates
        |-- snippets
        |   `-- panel.html
        |-- index.html
        |-- profile.html
        `-- base.html

    `-- theme
        |-- snippets
        |   |-- widget.html
        |   `-- extra.html
        |-- index.html
        `-- theme.html

And we want to create a single filesystem that will load a file from
``templates/`` only if it isn't found in ``theme/``. Here's how we could
do that::


    from fs.osfs import OSFS
    from fs.multifs import MultiFS

    theme_fs = MultiFS()
    theme_fs.add_fs('templates', OSFS('templates'))
    theme_fs.add_fs('theme', OSFS('theme'))


Now we have a ``theme_fs`` filesystem that presents a single view of both
directories::

    |-- snippets
    |   |-- panel.html
    |   |-- widget.html
    |   `-- extra.html
    |-- index.html
    |-- profile.html
    |-- base.html
    `-- theme.html


Masking paths
-------------

Sometimes an upper layer needs to withdraw a resource from publication
while the lower, archival layers keep their copies for administrators.
Rather than deleting anything, you can *mask* the path on the MultiFS::

    theme_fs.add_mask('snippets/panel.html')

A masked path, and everything beneath it, is then hidden from every read
operation on the combined filesystem -- single-file lookups such as
`~fs.multifs.MultiFS.getinfo` and `~fs.multifs.MultiFS.open`, as well as
directory traversals with `~fs.multifs.MultiFS.listdir` and
`~fs.multifs.MultiFS.scandir`. Masking a directory therefore covers all
of its descendants. Public resources that no layer has masked continue
to be resolved in priority order as usual. The current masks are
available from the read-only `~fs.multifs.MultiFS.masks` attribute and
can be removed again with `~fs.multifs.MultiFS.remove_mask`.

Unavailable backends
--------------------

If one of the child filesystems raises an error other than
`~fs.errors.ResourceNotFound` while it is being consulted, the MultiFS
keeps querying the remaining layers so that content they hold is still
returned. To make it clear that the answer may be incomplete, the
operation raises `~fs.errors.BackendUnavailable` once it has finished.
The exception records every failed backend in its ``failures``
attribute; for directory operations it also carries whatever entries
could still be assembled in its ``partial`` attribute.

Each read or traversal takes a snapshot of both the layer order and the
mask set when it begins, so reconfiguring the MultiFS halfway through a
traversal never produces a view that mixes the old and new
configuration.


.. autoclass:: fs.multifs.MultiFS
    :members:
