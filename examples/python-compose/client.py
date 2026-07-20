import json
import sys
import urllib.request


with urllib.request.urlopen(sys.argv[1], timeout=2) as response:
    payload = json.load(response)

assert payload == {
    "ok": True,
    "request_path": "/from-client",
    "service": "server",
    "topology": "sandbox-network-example",
}
print(json.dumps({"client": "passed", "response": payload}, sort_keys=True))
