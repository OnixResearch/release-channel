#!/usr/bin/env python3
"""Run the real-crypto loopback Sigsum mechanism pilot; no independence claim."""
import argparse
import json
import pathlib
import select
import subprocess
import tempfile


def request(executable, payload):
    result = subprocess.run([str(executable.resolve())], input=json.dumps(payload),
                            capture_output=True, text=True, timeout=15, check=True)
    if len(result.stdout) > 262144:
        raise RuntimeError("oversized provider response")
    return json.loads(result.stdout)


def exercise(args, directory, setup):
    policy = (directory / "policy").read_text()
    base = dict(policy=policy, secret=str(directory / "secret"), timeout_ms=10000)
    observations = []
    for value in (17, 29):
        statement = dict(metadata_hash=[value] * 32, signer=setup["signer"])
        appended = request(args.provider, dict(base, operation="append", statement=statement))
        if "evidence" not in appended:
            raise RuntimeError("append not proven: " + json.dumps(appended))
        evidence = appended["evidence"]
        checked = request(args.provider, dict(base, operation="verify", statement=statement, proof=evidence["proof"]))
        if checked.get("evidence") != evidence:
            raise RuntimeError("verification disagreed")
        observations.append(evidence)
    first, second = observations
    consistency = request(args.provider, dict(base, operation="consistency", previous=first["checkpoint"], observed=second["checkpoint"]))
    if "error" in consistency:
        raise RuntimeError("growing tree consistency failed: " + json.dumps(consistency))
    changed = dict(second["statement"], metadata_hash=[77] * 32)
    invalid = request(args.provider, dict(base, operation="verify", statement=changed, proof=second["proof"]))
    if invalid.get("kind") != "invalid":
        raise RuntimeError("changed metadata accepted")
    witness = next(line.split()[2] for line in policy.splitlines() if line.startswith("witness "))
    alien_policy = policy.replace(witness, "00" * 32)
    quorum_request = dict(base, operation="verify", statement=second["statement"], proof=second["proof"])
    quorum_request["policy"] = alien_policy
    quorum = request(args.provider, quorum_request)
    if quorum.get("kind") != "quorum":
        raise RuntimeError("missing trusted witness not rejected")
    return dict(evidence=observations, consistency=consistency, changed_metadata=invalid, missing_quorum=quorum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", type=pathlib.Path)
    parser.add_argument("log", type=pathlib.Path)
    parser.add_argument("receipt", type=pathlib.Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sigsum-localpilot-") as name:
        directory = pathlib.Path(name)
        process = subprocess.Popen([str(args.log.resolve()), name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            if not select.select([process.stdout], [], [], 10)[0]:
                raise RuntimeError("log startup deadline")
            setup = json.loads(process.stdout.readline(262144))
            receipt = exercise(args, directory, setup)
            receipt.update(upstream="ea106fe53c454bc5b8ece2ba56afc43d0f1f09dc",
                           claim="Same-host separate-process protocol mechanism only; NOT administrator/physical independence or production")
            with args.receipt.open("x") as output:
                json.dump(receipt, output, indent=2)
            print("PASS real Sigsum append, signer/inclusion/quorum verification, 1->2 consistency, metadata/quorum rejection")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
