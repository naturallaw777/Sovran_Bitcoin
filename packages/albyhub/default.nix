{ lib
, buildGoModule
, fetchFromGitHub
, stdenv
}:

buildGoModule rec {
  pname = "albyhub";
  version = "1.24.0";

  # sovran fork = upstream v1.24.0 + LND-only, no frontend, HOST bind,
  # always-private route hints (the customization lives in the fork's commits)
  src = fetchFromGitHub {
    owner = "naturallaw777";
    repo = "hub";
    tag = "sovran-1.24.0";
    # round 1: copy the "got: sha256-..." from the build error
    hash = "sha256-9l7xK7iA1p9qQRClgNV+eYg/vYJxbwBiRObeLRpyfDo=";
  };

  # `go mod vendor` strips the secp256k1-zkp cgo headers (include/), so use
  # the full module cache. Round 2: copy the "got: sha256-..." from the error
  proxyVendor = true;
  vendorHash = "sha256-U0NLVV0gH2IERqaGsJwE2f+iZQ35D+czH8mUKXSM4Wc=";

  subPackages = [ "cmd/http" ];

  # LND client needs cgo (secp256k1-zkp)
  buildInputs = [ (lib.getLib stdenv.cc.cc) ];

  # pin module downloads to a hermetic proxy and the local toolchain
  # (otherwise GOPROXY/GOTOOLCHAIN can leak into the builder env and the
  # cache comes back incomplete — the original failure)
  overrideModAttrs = (finalAttrs: previousAttrs: {
    modBuildPhase = ''
      runHook preBuild

      export GIT_SSL_CAINFO=$NIX_SSL_CERT_FILE
      export GOPROXY=https://proxy.golang.org,direct
      export GOSUMDB=sum.golang.org
      export GOTOOLCHAIN=local

      mkdir -p "$GOPATH/pkg/mod/cache/download"
      go mod download all

      export GOPROXY="file://$GOPATH/pkg/mod/cache/download"

      go list ./cmd/http

      mkdir -p vendor

      runHook postBuild
    '';
  });

  ldflags = [
    "-X github.com/getAlby/hub/version.Tag=${version}"
    "-s"
    "-w"
  ];

  postInstall = ''
    mv $out/bin/http $out/bin/albyhub
  '';

   preFixup = ''
    # Go's external linker bakes the sandbox build dir into the RPATH;
    # rewrite it to the real store paths before the fixup audit
    patchelf --set-rpath ${
      lib.makeLibraryPath [
        (lib.getLib stdenv.cc.cc)
        (lib.getLib stdenv.cc.libc)
      ]
    } $out/bin/albyhub
  '';

  meta.mainProgram = "albyhub";
}
