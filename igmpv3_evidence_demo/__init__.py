"""Offline IGMPv3 membership evidence model demo.

This package is a self-contained example living outside the Scapy core tree.
It crafts IGMPv3 membership reports with Scapy, stores them as a byte
transcript and evaluates whether a (port, group, source) subscription can be
proved from the transcript against a trusted provisioning policy.
"""

__all__ = ["config", "evidence_model", "transcript_build", "analyze"]
