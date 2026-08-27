from __future__ import annotations

import argparse
import json
import sys

from . import nwc_hub_manager as _mgr_mod
from .nwc_helpers import _nwc_domain, _nwc_validate_alias, _nwc_test_address


def _print(data) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nwc-wallet")
    sub = parser.add_subparsers(dest="cmd", required=True)

    create = sub.add_parser("create")
    create.add_argument("name")
    create.add_argument("alias")
    preset_group = create.add_mutually_exclusive_group()
    preset_group.add_argument("--receive-only", action="store_true")
    preset_group.add_argument("--limit-sats", type=int)

    sub.add_parser("list")

    drain = sub.add_parser("drain")
    drain.add_argument("wallet")

    delete = sub.add_parser("delete")
    delete.add_argument("wallet")

    addr = sub.add_parser("address")
    addr_sub = addr.add_subparsers(dest="address_cmd", required=True)
    addr_show = addr_sub.add_parser("show")
    addr_show.add_argument("alias")

    rotate = sub.add_parser("rotate")
    rotate.add_argument("wallet")

    sub.add_parser("health")

    args = parser.parse_args(argv)
    manager = _mgr_mod.get_manager()
    domain = _nwc_domain()

    if args.cmd == "list":
        try:
            wallets = manager.list_wallets(domain)
        except _mgr_mod.AlbyHubError as exc:
            print(f"Error: {exc.code} - {exc}", file=sys.stderr)
            return 1
        _print({"wallets": wallets})
        return 0

    if args.cmd == "health":
        result = manager.health()
        _print(result)
        return 0 if result.get("ok") else 1

    if args.cmd == "address" and args.address_cmd == "show":
        alias = args.alias.strip().lower()
        test = _nwc_test_address(alias)
        _print(test)
        return 0 if test.get("ok") else 1

    if args.cmd == "drain":
        try:
            result = manager.drain_wallet(args.wallet)
        except _mgr_mod.AlbyHubError as exc:
            print(f"Error: {exc.code} - {exc}", file=sys.stderr)
            return 1
        _print(result)
        return 0

    if args.cmd == "delete":
        try:
            result = manager.delete_wallet(args.wallet)
        except _mgr_mod.AlbyHubError as exc:
            print(f"Error: {exc.code} - {exc}", file=sys.stderr)
            return 1
        _print(result)
        return 0

    if args.cmd == "rotate":
        try:
            result = manager.rotate_wallet_secret(args.wallet)
        except _mgr_mod.AlbyHubError as exc:
            print(f"Error: {exc.code} - {exc}", file=sys.stderr)
            return 1
        _print({
            "wallet_id": result.get("wallet_id", ""),
            "pairing_uri": result.get("pairing_uri", ""),
            "message": result.get("message", "New NWC connection secret generated. Save it now — it will not be shown again."),
        })
        return 0

    if args.cmd == "create":
        alias = args.alias.strip().lower()
        if not _nwc_validate_alias(alias):
            print("Error: alias_invalid - Alias must be lowercase letters, digits, '_' or '-'.", file=sys.stderr)
            return 1
        access_preset = "send_receive_limited" if args.limit_sats is not None else "receive_only"
        try:
            result = manager.create_wallet(
                args.name.strip(),
                alias,
                access_preset,
                args.limit_sats if access_preset == "send_receive_limited" else None,
                domain,
            )
        except _mgr_mod.AlbyHubError as exc:
            print(f"Error: {exc.code} - {exc}", file=sys.stderr)
            return 1
        # Print the pairing URI once — this is the only time it is shown
        _print(
            {
                "wallet": result["wallet"],
                "pairing_uri": result.get("pairing_uri", ""),
                "message": "Keep the NWC connection secret private. It cannot be displayed again.",
                "result": result.get("result", {}),
            }
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
