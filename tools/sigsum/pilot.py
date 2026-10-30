#!/usr/bin/env python3
"""Opt-in network pilot; use an already-built pinned sigsum witness executable."""
import argparse
import json
import pathlib
import subprocess


def call(args, request):
    result = subprocess.run([str(args.executable.resolve())], input=json.dumps(request),
                            text=True, capture_output=True, timeout=args.timeout + 5, check=True)
    if len(result.stdout) > 262144 or len(result.stderr) > 262144:
        raise RuntimeError("provider output exceeded pilot limit")
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("policy", type=pathlib.Path)
    parser.add_argument("secret", type=pathlib.Path)
    parser.add_argument("signer", help="exact public Ed25519 key, hex")
    parser.add_argument("metadata", help="caller-selected metadata hash, hex")
    parser.add_argument("receipt", type=pathlib.Path)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    digest = bytes.fromhex(args.metadata)
    if len(digest) != 32:
        parser.error("metadata must be 32 bytes")
    base = dict(policy=args.policy.read_text(), secret=str(args.secret.resolve()),
                timeout_ms=args.timeout * 1000,
                statement=dict(metadata_hash=list(digest), signer=args.signer))
    appended = call(args, dict(base, operation="append"))
    if "evidence" not in appended:
        raise RuntimeError("append was not proven: " + json.dumps(appended))
    evidence = appended["evidence"]
    verified = call(args, dict(base, operation="verify", proof=evidence["proof"]))
    if verified.get("evidence") != evidence:
        raise RuntimeError("offline verification disagreed")
    changed = dict(base["statement"], metadata_hash=list(bytes([digest[0] ^ 1]) + digest[1:]))
    rejected = call(args, dict(base, operation="verify", proof=evidence["proof"], statement=changed))
    if rejected.get("kind") != "invalid":
        raise RuntimeError("changed metadata was not rejected")
    consistent = call(args, dict(base, operation="consistency", previous=evidence["checkpoint"],
                                observed=evidence["checkpoint"]))
    if "error" in consistent:
        raise RuntimeError("checkpoint self-consistency failed")
    receipt = dict(upstream="ea106fe53c454bc5b8ece2ba56afc43d0f1f09dc", evidence=evidence,
                   changed_metadata=rejected, consistency=consistent,
                   claim="Explicit supplied policy only; no local administrator independence")
    with args.receipt.open("x") as output:
        json.dump(receipt, output, indent=2)
    print("Sigsum inclusion, signer, policy quorum, tamper rejection, and self-consistency verified")


if __name__ == "__main__":
    main()
