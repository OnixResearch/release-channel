#!/usr/bin/env python3
"""Actual governed-publication pilot: GovernedPublisher over real TLS OCI and mirror stores,
a real Sigsum log, a durable channel-current CAS and independent read-back.

All roles share one OS/admin. No administrative independence, deployment or production claim.
"""
import argparse
import importlib.util
import json
import pathlib
import select
import subprocess
import tempfile


def load(name, relative):
    path = pathlib.Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exercise(args, root, transport, services):
    port, mirror, mirror_root, oci_root, log_setup = services
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
    control = root / "control"

    result = subprocess.run([str(args.governed), "smoke", str(fixtures), str(control)],
                            capture_output=True, text=True, timeout=600)
    if len(result.stdout) + len(result.stderr) > 1_048_576:
        raise RuntimeError("pilot output exceeds receipt bound")
    if result.returncode != 0:
        raise RuntimeError(f"governed publication smoke failed: {result.stderr.strip()}")
    receipt = {
        "profile": "release-channel-governed-publication-experimental-v1",
        "claim": "Actual GovernedPublisher staging, exact read-back, Sigsum witnessing and durable CAS; stale expected state rejected without durable change",
        "not_claimed": ["administrative independence", "physical-host independence", "deployment success",
                        "production readiness", "Mantle/Cairn producer chain"],
        "registry_image": transport.IMAGE,
        "stdout": result.stdout,
        "published_receipt": json.loads((control / "receipt.json").read_text()),
    }
    with args.receipt.open("x") as output:
        json.dump(receipt, output, indent=2)
    print(result.stdout, end="")
    print("PASS actual governed publication; shared-host experimental mechanism only")


def run(args, root):
    transport = load("release_transport_local", "transports/local.py")
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
        exercise(args, root, transport, (port, mirror, mroot, oroot, setup))
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
    for name in ("governed", "publisher", "index", "bridge", "log", "openssl", "receipt"):
        parser.add_argument(name, type=pathlib.Path)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if not value.is_absolute() or (name != "receipt" and not value.is_file()):
            parser.error(f"{name}: absolute existing capability required")
    if args.receipt.exists():
        parser.error("new receipt path required")
    with tempfile.TemporaryDirectory(prefix="release-channel-governed-") as temporary:
        run(args, pathlib.Path(temporary))


if __name__ == "__main__":
    main()
