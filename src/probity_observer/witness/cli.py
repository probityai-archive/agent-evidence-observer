"""``agent-evidence-witness``: run a witness, submit to one, and check what it returns.

Exit codes: 0 verified or done; 1 a record or proof was refused; 2 usage error;
3 equivocation detected (an evidence file names it); 4 the witness did not
answer, which decides nothing.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
from pathlib import Path

from probityai import dsse

from .checkpoint import EquivocationError, WitnessError, canonical, signer, verify_equivocation
from .client import WitnessClient, WitnessUnavailable
from .scope import KeyPin, verify_witnessed_record
from .server import WitnessLog, init_witness, make_server

REFUSED, EQUIVOCATION, UNAVAILABLE = 1, 3, 4


def _seed(path: Path) -> bytes:
    return bytes.fromhex(path.read_text().strip())


def _keygen(args: argparse.Namespace) -> int:
    seed = secrets.token_bytes(32)
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, seed.hex().encode("ascii") + b"\n")
    finally:
        os.close(descriptor)
    print(signer(seed).public_key.hex())
    return 0


def _init(args: argparse.Namespace) -> int:
    seed = _seed(args.seed) if args.seed else None
    print(init_witness(args.directory, args.origin, args.producer, seed=seed))
    return 0


def _serve(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    with WitnessLog(args.directory) as log:
        server = make_server(log, args.host, args.port)
        print(json.dumps({"origin": log.origin, "witnessKey": log.public_key, "port": server.server_port}), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


def _sign(args: argparse.Namespace) -> int:
    sys.stdout.buffer.write(dsse.sign(args.payload_type, args.payload.read_bytes(), signer(_seed(args.seed))) + b"\n")
    return 0


def _client(args: argparse.Namespace) -> WitnessClient:
    return WitnessClient(args.url, args.witness_key, args.origin, args.state)


def _submit(args: argparse.Namespace) -> int:
    producer = signer(_seed(args.seed)).public_key.hex()
    bundle, _ = _client(args).submit(args.envelope.read_bytes().strip(), args.claim_id, producer)
    sys.stdout.buffer.write(canonical(bundle) + b"\n")
    return 0


def _audit(args: argparse.Namespace) -> int:
    client = _client(args)
    for path in args.checkpoint:
        client.audit(path.read_bytes().strip())
    latest = client.latest()
    print(json.dumps({"origin": latest.origin, "size": latest.size, "rootHash": latest.root_hash.hex()}))
    return 0


def _verify(args: argparse.Namespace) -> int:
    bundle = json.loads(args.bundle.read_bytes())
    retained = args.retained.read_bytes().strip() if args.retained else None
    consistency = json.loads(args.consistency.read_bytes()) if args.consistency else None
    verdict = verify_witnessed_record(
        bundle,
        KeyPin(args.host_key, args.host_operator),
        KeyPin(args.witness_key, args.witness_operator),
        retained,
        consistency,
    )
    print(json.dumps({
        "claimId": verdict.claim_id,
        "payloadType": verdict.payload_type,
        "index": verdict.index,
        "size": verdict.checkpoint.size,
        **verdict.as_packet(),
    }))
    return 0


def _check_equivocation(args: argparse.Namespace) -> int:
    origin = verify_equivocation(json.loads(args.evidence.read_bytes()), args.witness_key)
    print(json.dumps({"fork": True, "origin": origin, "witnessKey": args.witness_key}))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-evidence-witness", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="write a new Ed25519 seed (mode 0600) and print its public key")
    keygen.add_argument("out", type=Path)
    keygen.set_defaults(run=_keygen)

    init = commands.add_parser("init", help="create a witness directory and print the witness key")
    init.add_argument("directory", type=Path)
    init.add_argument("--origin", required=True)
    init.add_argument("--producer", action="append", default=[], help="registered producer public key (hex)")
    init.add_argument("--seed", type=Path, help="use a seed written by keygen instead of a new one")
    init.set_defaults(run=_init)

    serve = commands.add_parser("serve", help="serve a witness directory over HTTP")
    serve.add_argument("directory", type=Path)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8470)
    serve.set_defaults(run=_serve)

    sign = commands.add_parser("sign", help="sign a payload as a DSSE envelope with a producer seed")
    sign.add_argument("payload", type=Path)
    sign.add_argument("--seed", type=Path, required=True)
    sign.add_argument("--payload-type", required=True)
    sign.set_defaults(run=_sign)

    for name, run, text in (
        ("submit", _submit, "submit a producer envelope and print the witnessed record"),
        ("audit", _audit, "check checkpoints from others and the latest one against the retained view"),
    ):
        command = commands.add_parser(name, help=text)
        command.add_argument("url")
        command.add_argument("--witness-key", required=True)
        command.add_argument("--origin", required=True)
        command.add_argument("--state", type=Path, required=True, help="file holding the retained checkpoint")
        command.set_defaults(run=run)
        if name == "submit":
            command.add_argument("envelope", type=Path)
            command.add_argument("--seed", type=Path, required=True, help="the producer's seed file")
            command.add_argument("--claim-id", required=True)
        else:
            command.add_argument("checkpoint", type=Path, nargs="*", help="checkpoint envelopes received elsewhere")

    verify = commands.add_parser("verify", help="verify a witnessed record offline and print its witness scope")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--host-key", required=True)
    verify.add_argument("--host-operator", required=True)
    verify.add_argument("--witness-key", required=True)
    verify.add_argument("--witness-operator", required=True)
    verify.add_argument("--retained", type=Path, help="an earlier checkpoint of the same log")
    verify.add_argument("--consistency", type=Path, help="the consistency proof from --retained to the bundle")
    verify.set_defaults(run=_verify)

    fork = commands.add_parser("check-equivocation", help="check a fork evidence record")
    fork.add_argument("evidence", type=Path)
    fork.add_argument("--witness-key", required=True)
    fork.set_defaults(run=_check_equivocation)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one command and map its outcome to the documented exit code."""
    args = _parser().parse_args(argv)
    try:
        return args.run(args)
    except EquivocationError as error:
        print(f"equivocation: {error}", file=sys.stderr)
        print(json.dumps(error.evidence), file=sys.stderr)
        return EQUIVOCATION
    except WitnessUnavailable as error:
        print(f"inconclusive: {error}", file=sys.stderr)
        return UNAVAILABLE
    except (WitnessError, dsse.DsseError, OSError, ValueError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return REFUSED


if __name__ == "__main__":
    sys.exit(main())
