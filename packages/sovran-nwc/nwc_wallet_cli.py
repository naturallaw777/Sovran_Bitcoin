from __future__ import annotations

import argparse
import json
import sys

from . import nwc_hub_manager as _mgr_mod
from .nwc_helpers import (
    _nwc_domain,
    _nwc_validate_alias,
    _nwc_test_address,
    _nwc_lnurl_bech32,
    _nwc_lightning_address,
    _render_qr_terminal,
)


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
    create.add_argument(
        "--qr",
        action="store_true",
        help="Print the Lightning Address QR code in the terminal (requires qrencode)",
    )

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

    # ── lnurl subcommand ──────────────────────────────────────────
    lnurl = sub.add_parser(
        "lnurl",
        help="Show the Lightning Address and bech32 LNURL for a wallet",
    )
    lnurl.add_argument("alias", help="The Lightning Address alias to look up")
    lnurl.add_argument(
        "--qr",
        action="store_true",
        help="Also print a QR code in the terminal (requires qrencode)",
    )
    lnurl.add_argument(
        "--lnurl-only",
        action="store_true",
        help="Print only the bech32 LNURL string (no JSON)",
    )
    lnurl.add_argument(
        "--address-only",
        action="store_true",
        help="Print only the Lightning Address (no JSON)",
    )

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

    if args.cmd == "lnurl":
        alias = args.alias.strip().lower()
        if not _nwc_validate_alias(alias):
            print(
                "Error: alias_invalid - Alias must be lowercase letters, digits, '_' or '-'.",
                file=sys.stderr,
            )
            return 1
        if not domain:
            print(
                "Error: domain_not_configured - Lightning Address domain is not configured.\n"
                "Set services.sovran-lnurl.domain or ensure /var/lib/domains/lightning exists.",
                file=sys.stderr,
            )
            return 1

        lightning_address = _nwc_lightning_address(alias, domain)
        lnurl_bech32 = _nwc_lnurl_bech32(alias, domain)

        # Quick output modes
        if args.address_only:
            print(lightning_address)
            if args.qr:
                qr = _render_qr_terminal(f"lightning:{lightning_address}")
                if qr:
                    print(qr)
                else:
                    print("Warning: qrencode not found — install it for QR display.", file=sys.stderr)
            return 0

        if args.lnurl_only:
            print(lnurl_bech32)
            if args.qr:
                # Uppercase for better QR scannability (LUD-01 recommends uppercase)
                qr = _render_qr_terminal(lnurl_bech32.upper())
                if qr:
                    print(qr)
                else:
                    print("Warning: qrencode not found — install it for QR display.", file=sys.stderr)
            return 0

        # Verify the alias actually exists on the Hub (non-fatal if it doesn't)
        alias_verified = False
        try:
            app = manager.find_app_by_alias(alias)
            alias_verified = app is not None
        except _mgr_mod.AlbyHubError:
            pass  # Hub unreachable — still show the address, it might work

        result = {
            "alias": alias,
            "lightning_address": lightning_address,
            "lnurl": lnurl_bech32,
            "alias_verified": alias_verified,
        }

        # Print QR code to terminal if requested
        if args.qr:
            qr = _render_qr_terminal(f"lightning:{lightning_address}")
            if qr:
                result["qr_terminal"] = True
                # Print the QR to stderr so it doesn't pollute JSON on stdout
                print(f"\n  Lightning Address: {lightning_address}\n", file=sys.stderr)
                print(qr, file=sys.stderr)
            else:
                result["qr_terminal"] = False
                print(
                    "Warning: qrencode not found — install it for QR display.",
                    file=sys.stderr,
                )

        _print(result)
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

        lightning_address = _nwc_lightning_address(alias, domain)

        output = {
            "wallet": result["wallet"],
            "pairing_uri": result.get("pairing_uri", ""),
            "lightning_address": lightning_address,
            "message": "Keep the NWC connection secret private. It cannot be displayed again.",
            "result": result.get("result", {}),
        }

        # Print QR code to terminal if requested
        if args.qr and lightning_address:
            qr = _render_qr_terminal(f"lightning:{lightning_address}")
            if qr:
                # Print the QR to stderr so it doesn't pollute JSON on stdout
                print(f"\n  Lightning Address: {lightning_address}\n", file=sys.stderr)
                print(qr, file=sys.stderr)
            else:
                print(
                    "Warning: qrencode not found — install it for QR display.",
                    file=sys.stderr,
                )
        elif args.qr and not lightning_address:
            print(
                "Warning: Cannot generate QR — Lightning Address domain is not configured.",
                file=sys.stderr,
            )

        _print(output)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
