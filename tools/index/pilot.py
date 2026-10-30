#!/usr/bin/env python3
"""Execute two explicitly configured experimental provider process-host pilots."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", required=True)
    parser.add_argument("--first", required=True)
    parser.add_argument("--second", required=True)
    args = parser.parse_args()
    with open(args.first, encoding="utf-8") as stream:
        first = json.load(stream)
    with open(args.second, encoding="utf-8") as stream:
        second = json.load(stream)
    if (first["program"], first["args"]) == (second["program"], second["args"]):
        parser.error("two separately configured provider capabilities are required")
    if first["consumer_store"] == second["consumer_store"]:
        parser.error("consumer capability roots must differ")
    for label, path in [("first", args.first), ("second", args.second)]:
        result = subprocess.run(
            [args.pilot, path], check=True, capture_output=True, text=True, timeout=120
        )
        receipt = json.loads(result.stdout)
        print(json.dumps({"configured_process_host": label, "receipt": receipt,
                          "administrative_independence_proven": False,
                          "physical_host_independence_proven": False}))


if __name__ == "__main__":
    main()
