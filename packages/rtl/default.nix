# Packaging adapted from fort-nix/nix-bitcoin commit 360e30fee.
# This local copy does not fetch or import nix-bitcoin.
{ lib
, stdenvNoCC
, nodejs_22
, nodejs-slim_22
, fetchNodeModules
, fetchurl
, makeWrapper
}:
let self = stdenvNoCC.mkDerivation {
  pname = "rtl";
  version = "0.15.12";

  src = fetchurl {
    url = "https://github.com/Ride-The-Lightning/RTL/archive/refs/tags/v${self.version}.tar.gz";
    hash = "sha256-4KrSsmeDYehxNIFIqucw7qIDrNNNYugFDvBopUvvHmE=";
  };

  passthru = {
    nodejs = nodejs_22;
    nodejsRuntime = nodejs-slim_22;

    nodeModules = fetchNodeModules {
      inherit (self) src nodejs;
      # TODO-EXTERNAL: Remove `npmFlags` when no longer required
      # See: https://github.com/Ride-The-Lightning/RTL/issues/1182
      npmFlags = "--legacy-peer-deps";
      hash = "sha256-PcYYPZOBLIfRKSGb6+LoEEytD+eMI7sTfoDm4huOdFE=";
    };
  };

  nativeBuildInputs = [
    makeWrapper
  ];

  phases = "unpackPhase patchPhase installPhase";

  # The prebuilt Angular app uses <base href="/rtl/"> and PathLocationStrategy.
  # Express still catch-all-serves index.html at `/`, so a visit to the
  # documented loopback URL or the onion vhost (port 80 → RTL) boots Angular
  # on `/` and renders a blank page. Send `/` to `/rtl/` before the API mount.
  postPatch = ''
    substituteInPlace backend/utils/app.js \
      --replace-fail \
      "this.app.use(this.common.baseHref + '/api', sharedRoutes);" \
      "this.app.get('/', (req, res) => res.redirect(this.common.baseHref + '/')); this.app.use(this.common.baseHref + '/api', sharedRoutes);"
  '';

  # `src` already contains the precompiled frontend and backend.
  # Copy all files required for packaging, like in
  # https://github.com/Ride-The-Lightning/RTL/blob/master/dockerfiles/Dockerfile
  installPhase = ''
    dest=$out/lib/node_modules/rtl
    mkdir -p $dest
    cp -r \
      rtl.js \
      package.json \
      frontend \
      backend \
      ${self.nodeModules}/lib/node_modules \
      $dest

    makeWrapper ${self.nodejsRuntime}/bin/node "$out/bin/rtl" \
      --add-flags "$dest/rtl.js"

    runHook postInstall
  '';

  meta = with lib; {
    description = "A web interface for LND, c-lightning and Eclair";
    homepage = "https://github.com/Ride-The-Lightning/RTL";
    license = licenses.mit;
    maintainers = with maintainers; [ nixbitcoin erikarvstedt ];
    platforms = platforms.unix;
  };
}; in self
