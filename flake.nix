{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      with pkgs; {
        devShells.default = mkShell rec {
          packages = [
            pkg-config
            python3.pkgs.pyelftools
            meson
            ninja
	    ccls
            clang

            stdenv.cc.cc.lib
            elfutils
            zeromq
            jansson
            libbpf
            elfutils
            libpcap
            numactl
            openssl
            zlib
          ];

	  LD_LIBRARY_PATH= lib.makeLibraryPath packages;
        };
      }
    );
}
