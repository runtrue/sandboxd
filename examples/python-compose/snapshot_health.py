import pathlib
import sys


counter_path = pathlib.Path("/tmp/snapshot-counter")
if not counter_path.exists() or int(counter_path.read_text()) < 1:
    sys.exit(1)
