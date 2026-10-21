# Sovran NWC — Nix-native Nostr Wallet Connect (NIP-47) daemon, LNURL-pay
# service, and wallet management CLI for LND.
#
# Pure-stdlib Python (zero external Go/npm/pip dependencies). Talks directly to
# LND's local REST API using a scoped macaroon and stores isolated sub-wallet
# ledgers in SQLite (WAL mode).
#
# Binaries provided:
#   nwc-daemon  — NIP-47 NWC wallet server + local management API (127.0.0.1:18080)
#   albyhub     — backwards-compatible alias for nwc-daemon
#   nwc-lnurl   — public LNURL-pay service (binds 127.0.0.1:8181 by default)
#   nwc-wallet  — CLI to create/list/drain/delete/rotate NWC wallets
{ lib
, stdenvNoCC
, python3
}:

stdenvNoCC.mkDerivation {
  pname = "sovran-nwc";
  version = "2.0.1";

  src = ./.;

  # Pure-stdlib unit and integration tests (BIP-340, NIP-04, NIP-44 v2,
  # NIP-47 daemon, least-privilege token scopes, wallet lookup, send-cap).
  doCheck = true;
  nativeCheckInputs = [ python3 ];

  checkPhase = ''
    runHook preCheck
    python3 tests/test_nostr_crypto.py
    python3 tests/test_nwc_daemon.py
    python3 tests/test_wallet_lookup.py
    python3 tests/test_send_cap.py
    runHook postCheck
  '';

  installPhase = ''
    runHook preInstall

    install -Dm 644 -t $out/lib/sovran-nwc/sovran_nwc \
      nwc_helpers.py \
      nwc_audit.py \
      nwc_nostr.py \
      nwc_lnd.py \
      nwc_daemon.py \
      nwc_hub_manager.py \
      nwc_lnurl_service.py \
      nwc_wallet_cli.py
    touch $out/lib/sovran-nwc/sovran_nwc/__init__.py

    mkdir -p $out/bin
    cat > $out/bin/nwc-daemon <<LAUNCHER
    #!${python3}/bin/python3
    import os, sys
    sys.path.insert(0, os.path.join("$out", "lib", "sovran-nwc"))
    from sovran_nwc.nwc_daemon import main
    main()
    LAUNCHER
    cat > $out/bin/nwc-lnurl <<LAUNCHER
    #!${python3}/bin/python3
    import os, sys
    sys.path.insert(0, os.path.join("$out", "lib", "sovran-nwc"))
    from sovran_nwc.nwc_lnurl_service import main
    main()
    LAUNCHER
    cat > $out/bin/nwc-wallet <<LAUNCHER
    #!${python3}/bin/python3
    import os, sys
    sys.path.insert(0, os.path.join("$out", "lib", "sovran-nwc"))
    from sovran_nwc.nwc_wallet_cli import main
    sys.exit(main())
    LAUNCHER
    chmod +x $out/bin/nwc-daemon $out/bin/nwc-lnurl $out/bin/nwc-wallet
    ln -s nwc-daemon $out/bin/albyhub

    runHook postInstall
  '';

  # Runtime dependency: python3 (stdlib only, no pip packages)
  passthru.python = python3;

  meta = {
    description = "Sovran NWC — Nix-native Nostr Wallet Connect daemon, LNURL service, and wallet CLI for LND";
    mainProgram = "nwc-daemon";
    platforms = lib.platforms.unix;
  };
}
