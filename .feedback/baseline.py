import subprocess
import sys

raise SystemExit(
    subprocess.call(
        [
            sys.executable,
            *[
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "-q",
                "tests/testCandidateSafeguards.py",
                "tests/testSmdaReportPickle.py",
                "tests/testAbsoluteDataRefs.py",
                "tests/testArmReturns.py",
            ],
        ]
    )
)
