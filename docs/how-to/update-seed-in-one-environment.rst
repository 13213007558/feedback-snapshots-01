##########################################
 Update seed packages in one environment
##########################################

A build service is sometimes allowed to refresh the seed components (``pip``, ``setuptools`` and ``wheel``) of one
specific virtual environment only. Other environments on the same machine may link the very same wheel image from the
shared application data folder and can start while the update runs. This guide explains how the update stays scoped to
the target environment, how a failure is contained, and how to prove which version each environment really runs.

.. note::

    The :mod:`tasks.demo_seed_update_isolation` script reproduces every step below with two tiny local wheels and two
    environments and prints the real imports, launcher destinations and file listings it compares. Run it from the
    repository root with ``python tasks/demo_seed_update_isolation.py`` (add ``--keep`` to retain its temporary
    workspace).

****************
 The shared image
****************

With the default ``app-data`` seeder, virtualenv extracts each seed wheel once into an image under the application data
folder and installs it into every environment from that image. The image path keys on the installer and the wheel, so
two install strategies leave different evidence of file ownership:

* the copy installer (``CopyPipInstall``) duplicates the image files into the environment's ``site-packages``; the
  environment owns real files and directories;
* the symlink installer (``--symlink-app-data`` / ``SymlinkPipInstall``) puts links in ``site-packages`` that point at
  the shared, read-only image; the environment owns the links, not the package files.

Because a linked environment reads the shared image at startup, the update must never modify an image in place. The new
image is built in a private staging directory and only published with an atomic ``os.replace`` once it is complete.

******************
 The update process
******************

#. Pick the target environment and the new, locally verified wheel. Keep every other environment on its existing
   configuration; do not pass their paths to the update.
#. Build the new wheel image into staging and fix up its ``RECORD`` there. A failure at this stage only removes the
   staging directory: no image is published and no environment is touched.
#. Publish the image atomically, then run the installer for the target environment. It uninstalls the previous version
   and writes the new install record (``*.dist-info``, ``RECORD``, ``INSTALLER``) and console launchers only inside the
   target environment.
#. Leave linked environments alone. Their links still resolve to the old image, which the new image never overwrote
   because each wheel version has its own image directory.

******************
 Failure protection
******************

If the build fails before the install record is written, virtualenv cleans the staging directory in a ``finally``
block and raises. After such a failure:

* no partial or empty new image is present, so a later run rebuilds it from scratch;
* the target environment keeps its previous ``*.dist-info`` and its old console launcher, which still runs;
* the linked environment still resolves to the same shared image and imports the old version;
* the project's own scripts are unaffected because the installer writes only the distribution's recorded files and
  generated entry points inside the target environment.

The same containment applies when ``virtualenv --upgrade-embed-wheels`` cannot refresh a bundled wheel: the command
logs one ``could not upgrade`` error per distribution and exits with status ``1`` instead of leaving a half-updated
state.

********************************
 Proving which version is in use
********************************

Check the running interpreter rather than trusting a file name, in each environment separately:

.. code-block:: console

    $ target-env/bin/python -c "import pip, importlib.metadata as m; print(pip.__version__, m.version('pip'))"
    $ other-env/bin/python  -c "import pip, importlib.metadata as m; print(pip.__version__, m.version('pip'))"
    $ target-env/bin/pip --version

Then confirm ownership and the launchers' destinations:

* in the copied environment ``site-packages`` holds regular files; in the linked one ``ls -l`` shows symlinks whose
  target is the shared image under the application data folder;
* each environment's console launcher carries its own interpreter in its shebang, so the two launchers are independent
  files even when the package files are shared;
* ``*.dist-info/RECORD`` lists the copied files for a copy install and the linked entries for a symlink install.

After a successful update the target reports the new version through the import, the metadata and its launcher, while a
linked environment keeps importing and launching the old version from the untouched shared image.
