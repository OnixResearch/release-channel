#!/usr/bin/env python3
"""Actual OnixOS consumer pilot with real TLS transports, Sigsum and external index.

All roles share one OS/admin; provider state is outside the consumer rollback root.
No admin/physical independence, deployment success or production claim.
"""
import argparse
import importlib.util
import json
import pathlib
import select
import subprocess
import tempfile


def load_transport():
    path = pathlib.Path(__file__).resolve().parents[1] / "transports" / "local.py"
    spec = importlib.util.spec_from_file_location("release_transport_local", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CASES = ("expired", "revoked", "split", "supersession")


def exercise(args, root, services, case):
    transport, port, mirror, mirror_root, oci_root, log_setup = services
    config = {
        "oci": transport.endpoint(port, oci_root, 1, True),
        "mirror": transport.endpoint(mirror.server_port, mirror_root, 2, False),
        "witness_program": str(args.bridge), "witness_policy": str(root / "sigsum" / "policy"),
        "witness_secret": str(root / "sigsum" / "secret"), "witness_signer": log_setup["signer"],
        "index_program": str(args.index), "mirror_directory": str(root / "mirror"),
    }
    path = root / "setup.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    fixtures = root / "fixtures"
    subprocess.run([str(args.publisher), "prepare", str(fixtures), str(path)], check=True, timeout=30)
    result = subprocess.run(["python3", str(args.smoke), str(args.consumer), str(fixtures), case],
                            capture_output=True, text=True, timeout=1200)
    if len(result.stdout) + len(result.stderr) > 1_048_576:
        raise RuntimeError("pilot output exceeds receipt bound")
    if result.returncode != 0:
        raise RuntimeError(f"{case} consumer matrix failed: {result.stderr.strip()[-4000:]}")
    return {"case": case, "stdout": result.stdout}


def receipt_for(args, cases):
    receipt = {
        "profile": "release-channel-experimental-separate-process-v1",
        "claim": "Actual consumer admission/rotation/recovery and consumer-only rollback rejection; common OS/admin",
        "not_claimed": ["administrative independence", "physical-host independence", "deployment success", "production readiness"],
        "registry_image": load_transport().IMAGE,
        "provider_rollback_domain": "Separate private provider capability root outside consumer-store rollback root",
        "cases": cases,
        "phases": ["first", "second", "rotated", "control", "expired", "revoked", "split", "recovery"],
        "facts": "Publisher hooks perform actual dual-path upload/readback, real Sigsum append/proof verification and authenticated index reservation/finalization; negative expired/revoked metadata never advances index",
    }
    with args.receipt.open("x") as output:
        json.dump(receipt, output, indent=2)
    for result in cases:
        print(result["stdout"], end="")
    print("PASS genuine publisher + OnixOS consumer; shared-host experimental mechanism only")


def run(args, root, case):
    transport = load_transport()
    for name in ("oci", "mirror", "sigsum"):
        (root / name).mkdir(mode=0o700)
    okey, ocert, oroot = transport.certificate(root / "oci", str(args.openssl))
    mkey, mcert, mroot = transport.certificate(root / "mirror", str(args.openssl))
    mirror = transport.mirror(root / "mirror", mkey, mcert)
    container = None
    log = None
    try:
        container, port = transport.registry(root / "oci", okey, ocert)
        transport.ready(port)
        log = subprocess.Popen([str(args.log), str(root / "sigsum")],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if not select.select([log.stdout], [], [], 10)[0]:
            raise RuntimeError("actual Sigsum log startup deadline")
        setup = json.loads(log.stdout.readline(262144))
        return exercise(args, root, (transport, port, mirror, mroot, oroot, setup), case)
    finally:
        mirror.shutdown()
        mirror.server_close()
        if log is not None:
            log.terminate()
            try:
                log.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log.kill()
                log.wait(timeout=5)
        if container:
            subprocess.run(["docker", "stop", container], check=True, timeout=30,
                           stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("consumer", "smoke", "publisher", "index", "bridge", "log", "openssl", "receipt"):
        parser.add_argument(name, type=pathlib.Path)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if not value.is_absolute() or (name != "receipt" and not value.is_file()):
            parser.error(f"{name}: absolute existing capability required")
    if args.receipt.exists():
        parser.error("new receipt path required")
    cases = []
    # Each case uses fresh services, provider roots, namespaces and signing authorities.
    for case in CASES:
        with tempfile.TemporaryDirectory(prefix=f"release-channel-onixos-{case}-") as temporary:
            cases.append(run(args, pathlib.Path(temporary), case))
    receipt_for(args, cases)


if __name__ == "__main__":
    main()
