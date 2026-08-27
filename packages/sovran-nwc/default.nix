# Sovran NWC tooling — self-hosted LNURL-over-NWC service + wallet CLI.
#
# Pure-stdlib Python extracted from Sovran_SystemsOS' Hub web app, decoupled
# so it can run on any NixOS host. Talks to Alby Hub's local API and LND.
#
# Binaries provided:
#   nwc-lnurl   — public LNURL-pay service (binds 127.0.0.1:8181 by default)
#   nwc-wallet  — CLI to create/list/drain/delete NWC wallets via Alby Hub
{ lib
, stdenvNoCC
, python3
}:

stdenvNoCC.mkDerivation {
  pname = "sovran-nwc";
  version = "1.1.3";

  src = ./.;

  installPhase = ''
    runHook preInstall

    install -Dm 644 -t $out/lib/sovran-nwc/sovran_nwc \
      nwc_helpers.py \
      nwc_audit.py \
      nwc_hub_manager.py \
      nwc_lnurl_service.py \
      nwc_wallet_cli.py
    touch $out/lib/sovran-nwc/sovran_nwc/__init__.py

    mkdir -p $out/bin
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
    chmod +x $out/bin/nwc-lnurl $out/bin/nwc-wallet

    runHook postInstall
    '';

  # Runtime dependency: python3 (stdlib only, no pip packages)
  passthru.python = python3;

  meta = {
    description = "Sovran NWC tooling — LNURL service and wallet CLI for Alby Hub + LND";
    mainProgram = "nwc-lnurl";
    platforms = lib.platforms.unix;
  };
}
