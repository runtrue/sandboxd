import os
import signal
import sys
import time


mode = sys.argv[1]

if mode == "memory":
    allocation = bytearray(256 * 1024 * 1024)
    allocation[0] = 1
    print("memory limit failed", flush=True)
    time.sleep(5)
elif mode == "output":
    remaining = 2 * 1024 * 1024
    chunk = b"x" * 65536
    while remaining:
        written = os.write(1, chunk[:remaining])
        remaining -= written
elif mode == "processes":
    children = []
    bounded_at = None
    try:
        for index in range(100):
            try:
                child = os.fork()
            except OSError:
                bounded_at = index
                break
            if child == 0:
                time.sleep(10)
                os._exit(0)
            children.append(child)
    finally:
        for child in children:
            os.kill(child, signal.SIGKILL)
        for child in children:
            os.waitpid(child, 0)
    assert bounded_at is not None and bounded_at <= 32, bounded_at
    print(f"process-limit-passed:{bounded_at}")
else:
    raise ValueError(mode)
