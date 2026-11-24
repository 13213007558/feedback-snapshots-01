Mount Filesystem
================

A Mount FS is a *virtual* filesystem which can seamlessly map
sub-directories on to other filesystems.

For example, lets say we have two filesystems containing config files
and resources respectively::

   [config_fs]
   |-- config.cfg
   `-- defaults.cfg

   [resources_fs]
   |-- images
   |   |-- logo.jpg
   |   `-- photo.jpg
   `-- data.dat

We can combine these filesystems in to a single filesystem with the
following code::

    from fs.mountfs import MountFS
    combined_fs = MountFS()
    combined_fs.mount('config', config_fs)
    combined_fs.mount('resources', resources_fs)

This will create a filesystem where paths under ``config/`` map to
``config_fs``, and paths under ``resources/`` map to ``resources_fs``::

    [combined_fs]
    |-- config
    |   |-- config.cfg
    |   `-- defaults.cfg
    `-- resources
        |-- images
        |   |-- logo.jpg
        |   `-- photo.jpg
        `-- data.dat

Now both filesystems may be accessed with the same path structure::

    print(combined_fs.gettext('/config/defaults.cfg'))
    read_jpg(combined_fs.open('/resources/images/logo.jpg', 'rb')

Replacing a Mount
-----------------

A single mount can be replaced without touching the others with
``remount``. The previous filesystem is returned *open* rather than
closed: handles that were opened before the switch keep working against
the old filesystem, while every new request resolves to the replacement.
This lets an in-flight read or copy finish under its original
authorization instead of having its writes leak into the new space::

    old_fs = combined_fs.remount('config', new_config_fs)
    # ... drain existing handles against old_fs ...
    old_fs.close()

Use ``unmount`` to remove a mount entirely, keeping the detached
filesystem open with ``close=False`` when you need to drain it first.

.. autoclass:: fs.mountfs.MountFS
   :members:

.. autoexception:: fs.mountfs.MountError
   :show-inheritance:
