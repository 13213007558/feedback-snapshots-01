# FAIL-CLOSED: this file is intentionally invalid Ruby.
# A parse failure (or prism->ruby_parser fallback) must surface as an error,
# never as a scan with "no vulnerabilities".
def broken(
