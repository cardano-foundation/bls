{
  description = "Dev shell for groth16-prover with Verus verification support";

  inputs = {
    nixpkgs.url = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # ------------------------------------------------------------------
        # Z3 4.16.0 — build from source because Nixpkgs ships 4.8.x.
        # ------------------------------------------------------------------
        z3_4_16 = pkgs.stdenv.mkDerivation rec {
          pname = "z3";
          version = "4.16.0";

          src = pkgs.fetchFromGitHub {
            owner = "Z3Prover";
            repo = "z3";
            rev = "z3-${version}";
            sha256 = "1xwf7yck0lqy4l45mbr8ia3nn384dkq105wcr5k730k09kg5fy0f";
          };

          nativeBuildInputs = [ pkgs.cmake pkgs.python3 ];

          configurePhase = ''
            python3 scripts/mk_make.py --prefix=$out
            cd build
          '';

          buildPhase = ''
            make -j$NIX_BUILD_CORES
          '';

          installPhase = ''
            make install
          '';

          # Z3's build system doesn't use cmake directly in the source root;
          # we use the provided mk_make.py script.
          dontUseCmakeConfigure = true;
        };

        # ------------------------------------------------------------------
        # Verus — download the prebuilt x86_64-linux release and patch
        # its interpreter / RPATH so it uses Nix glibc & libstdc++.
        # ------------------------------------------------------------------
        verus = pkgs.stdenv.mkDerivation rec {
          pname = "verus";
          version = "0.2026.09.20.aef82ed";

          src = pkgs.fetchurl {
            url = "https://github.com/verus-lang/verus/releases/download/release/${version}/verus-${version}-x86-linux.zip";
            sha256 = "0yp996cwznji7cp4zv3z7hvj09665ia6lm7pk2sndj047i2r82a2";
          };

          nativeBuildInputs = [ pkgs.unzip pkgs.patchelf ];
          buildInputs = [ pkgs.glibc pkgs.gcc.cc.lib ];

          dontUnpack = true;
          dontBuild = true;

          installPhase = ''
            mkdir -p $out
            unzip -q $src -d $out
            # Flatten the single top-level directory that the archive creates.
            mv $out/verus-x86-linux/* $out/
            rmdir $out/verus-x86-linux || true

            # Patch every ELF executable so it links against Nix libraries.
            for bin in $out/verus $out/cargo-verus $out/air $out/verusdoc $out/deps/verus-*; do
              if [ -f "$bin" ] && [ -x "$bin" ]; then
                patchelf --set-interpreter "${pkgs.glibc}/lib/ld-linux-x86-64.so.2" \
                         --set-rpath "${pkgs.glibc}/lib:${pkgs.gcc.cc.lib}/lib" \
                         "$bin" || true
              fi
            done
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain (stable + rustup to install the exact version Verus needs)
            rustup
            rustc
            cargo
            rustfmt
            clippy

            # Verus + Z3
            verus
            z3_4_16

            # Build tools
            cmake
            pkg-config
            openssl
            patchelf

            # Misc
            git
            gnumake
          ];

          shellHook = ''
            export VERUS_Z3_PATH="${z3_4_16}/bin/z3"
            echo "=== groth16-prover dev shell ==="
            echo "Verus: $(verus --version 2>/dev/null || echo 'not in PATH')"
            echo "Z3:    $(z3 --version 2>/dev/null || echo 'not in PATH')"
            echo "Rust:  $(rustc --version)"
            echo ""
            echo "To run Verus on a file:"
            echo "  verus clis/trusted-setup/src/verus_smoke.rs --crate-type=lib --features verus"
            echo ""
            echo "To verify the whole crate:"
            echo "  cd clis/trusted-setup && verus src/lib.rs --crate-type=lib --features verus"
            echo ""
            echo "Normal cargo build (no Verus overhead):"
            echo "  cargo check && cargo test"
          '';
        };

        packages.verus = verus;
        packages.z3_4_16 = z3_4_16;
      });
}
