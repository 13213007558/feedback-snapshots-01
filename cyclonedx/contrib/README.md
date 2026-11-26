# CycloneDX Contrib Extensions

This directory contains community-contributed functionality that extends the capabilities of the CycloneDX core library.  
Unlike the modules in `../`, these features are not part of the official CycloneDX specification and may vary in stability, scope, or compatibility.

## Contents
- Utilities, helpers, and experimental features developed by the community
- Optional add-ons that may facilitate or enhance use of the CycloneDX core library
- Code that evolves independently of the CycloneDX specification

## Offline risk review

`cyclonedx.contrib.risk_review` provides an approval-aware reconciliation entry
point. The reviewer performs no network I/O: the application supplies an
in-memory or local parser/resolver, and the parser is called only after the
approval policy accepts a reference.

Reports separate locally verified dependency relationships, obtained materials
that can be matched back to their references, and missing-approval or
unverifiable references. Failure reasons remain on the original reference and
dependency position so an incomplete branch does not erase confirmed results
from another branch.

Run the self-checking in-memory scenario from the repository root:

```sh
.venv/bin/python examples/risk_review_offline_review.py
```

## Notes
- Contrib modules are optional and not required for strict compliance with the CycloneDX standard.
- They may change more frequently than the core and are not guaranteed to follow the same versioning rules.
- Users should evaluate these modules carefully and consult documentation or source comments for details.

## Contributing
Contributions are welcome. To add an extension:
1. Follow the contribution guidelines in the main repository.
2. Place your code in a clearly named subfolder or file under `contrib/`.
3. Provide documentation and tests to ensure clarity and maintainability.  
