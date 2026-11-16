"""Boundary verification for the OLE writer used by Agile encryption.

These modules validate the on-disk OLE/CFB sector layout produced by
:class:`msoffcrypto.method.container.ecma376_encrypted.ECMA376Encrypted`,
independently of msoffcrypto's own reader, across the layout transition
boundaries (mini-stream cutoff, regular FAT growth and DIFAT extension).
"""
