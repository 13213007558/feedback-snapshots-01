Add ``--approved-source`` to explicitly restrict which URLs or local paths
packages may be installed from, and ``--approved-build-tool`` so
administrators can exempt vetted build tools from these rules. The source
rules are inherited by the isolated build environment when build
dependencies are installed.
