Add ``--approved-source`` to restrict installs to packages obtained from the
given URLs or local paths. Candidates that satisfy the version constraints but
come from any other source are rejected before preparation, and resolution
errors distinguish a missing version from a version refused by this rule.
