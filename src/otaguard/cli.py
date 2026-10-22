"""Read-only deterministic command-line interface for Rudy OTA Guard."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .core import (GuardError, abort_release, commit_release, load_json,
                   rotate_root, stage_release, verify_release)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise GuardError("usage", "invalid command arguments")


def _positive_epoch(text: str) -> int:
    try:
        value = int(text, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("invalid epoch")
    if str(value) != text or value < 1 or value > (1 << 53) - 1:
        raise argparse.ArgumentTypeError("invalid epoch")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="otaguard")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for name in ("verify", "stage"):
        sub = commands.add_parser(name)
        sub.add_argument("--manifest", required=True)
        sub.add_argument("--root", required=True)
        sub.add_argument("--state", required=True)
        sub.add_argument("--payload", required=True)
        sub.add_argument("--now", required=True, type=_positive_epoch)
    commit = commands.add_parser("commit")
    commit.add_argument("--state", required=True)
    commit.add_argument("--healthy", required=True, action="store_true")
    abort = commands.add_parser("abort")
    abort.add_argument("--state", required=True)
    rotate = commands.add_parser("rotate-root")
    rotate.add_argument("--manifest", required=True)
    rotate.add_argument("--root", required=True)
    rotate.add_argument("--now", required=True, type=_positive_epoch)
    return parser


def _emit(value: object) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")


def _run(args: argparse.Namespace) -> object:
    if args.command in ("verify", "stage"):
        envelope = load_json(args.manifest)
        root = load_json(args.root)
        state = load_json(args.state)
        if args.command == "verify":
            return verify_release(envelope, root, state, args.payload, args.now)
        return stage_release(envelope, root, state, args.payload, args.now)
    if args.command == "commit":
        return commit_release(load_json(args.state), True)
    if args.command == "abort":
        return abort_release(load_json(args.state))
    if args.command == "rotate-root":
        return rotate_root(load_json(args.manifest), load_json(args.root), args.now)
    raise GuardError("usage", "unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = _run(args)
        _emit(result)
        return 0
    except GuardError as exc:
        _emit({"error": {"code": exc.code, "message": exc.message}})
        return 3 if exc.code == "io" else 2
    except (OSError, ValueError, TypeError):
        _emit({"error": {"code": "io", "message": "unable to process input"}})
        return 3
