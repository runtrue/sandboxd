import http.client
import json
import pathlib
import time


counter_path = pathlib.Path("/tmp/snapshot-counter")
counter = int(counter_path.read_text()) if counter_path.exists() else 0
connection = http.client.HTTPConnection("server", 8080, timeout=2)

while True:
    connection.request("GET", "/from-snapshot-client")
    response = connection.getresponse()
    payload = json.loads(response.read())
    if payload.get("ok") is not True or payload.get("service") != "server":
        raise RuntimeError(f"unexpected server response: {payload!r}")
    counter += 1
    counter_path.write_text(f"{counter}\n")
    time.sleep(0.1)
