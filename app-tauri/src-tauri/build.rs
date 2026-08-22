use std::path::PathBuf;
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let manifest = PathBuf::from(
            std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is missing"),
        );
        let repository = manifest
            .parent()
            .and_then(|path| path.parent())
            .expect("Tauri manifest must be inside the OsaGuard repository");
        let target = std::env::var("TARGET").expect("Cargo TARGET is missing");
        let bridge_output =
            PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo OUT_DIR is missing"))
                .join("appbridge");
        let bridge_script = repository.join("scripts/build-appbridge.sh");
        let status = Command::new("/bin/sh")
            .arg(&bridge_script)
            .arg(&target)
            .arg(&bridge_output)
            .status()
            .expect("failed to start the OsaGuard native bridge build");
        assert!(status.success(), "OsaGuard native bridge build failed");

        cc::Build::new()
            .file("src/accessibility_darwin.c")
            .warnings(true)
            .compile("osaguard_accessibility");
        println!("cargo:rustc-link-search=native={}", bridge_output.display());
        println!("cargo:rustc-link-lib=static=osaguard_appbridge");
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rerun-if-changed={}", bridge_script.display());
        println!(
            "cargo:rerun-if-changed={}",
            repository.join("cmd/osaguard-appbridge").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repository.join("internal/autotype").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repository.join("internal/darwinbridge").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repository.join("internal/secureenroll").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repository.join("go.mod").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repository.join("go.sum").display()
        );
        println!("cargo:rerun-if-changed=src/accessibility_darwin.c");
    }

    tauri_build::build()
}
