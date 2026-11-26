Add ``--receipt-dir`` and ``--diagnostic-dir`` so a creation can leave a shareable receipt of the steps it reached and
the materials it reclaimed. The receipt names no directory or cache location and carries an identifier that links it to
a private diagnostic holding the actual files. A failed creation now reclaims only the materials it introduced, never
pre-existing content of the destination or another job's finished environment in the same parent directory.
