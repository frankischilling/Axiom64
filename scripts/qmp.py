"""Small synchronous QEMU monitor client used by the boot harness."""
import json
import socket


class Qmp:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(5)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile("rwb")
        json.loads(self.stream.readline())
        self.sequence = 0
        self.command("qmp_capabilities")

    def command(self, name, arguments=None):
        self.sequence += 1
        request = {"execute": name, "id": self.sequence}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode() + b"\n")
        self.stream.flush()
        while True:
            response = json.loads(self.stream.readline())
            if response.get("id") != self.sequence:
                continue
            if "error" in response:
                raise RuntimeError(response["error"])
            return response.get("return")

    def close(self):
        self.stream.close()
        self.socket.close()


if __name__ == "__main__":
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser()
    parser.add_argument("socket")
    parser.add_argument("--screenshot")
    args = parser.parse_args()
    client = Qmp(args.socket)
    print(client.command("query-status"))
    if args.screenshot:
        client.command("screendump", {"filename": str(Path(args.screenshot).resolve()), "format": "png"})
    client.close()
