import os, subprocess, sys
os.chdir("tests")
raise SystemExit(subprocess.call([sys.executable,"-bb","-m","unittest","discover"]))
