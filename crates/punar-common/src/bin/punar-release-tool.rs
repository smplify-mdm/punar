#![forbid(unsafe_code)]

//! Small build/CI utility for Punar's detached release signatures.
//!
//! Production private-key custody is intentionally outside this repository.
//! The release-bundle build uses this utility with an ephemeral 32-byte seed,
//! publishes only the raw Ed25519 public key, and deletes the seed when the
//! build exits.

use std::env;
use std::fs;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use punar_common::update::{
    ReleaseKeySet, verify_channel_metadata, verify_reader, verify_release_manifest,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         punar-release-tool public-key SEED OUTPUT\n  \
         punar-release-tool sign SEED DOCUMENT SIGNATURE\n  \
         punar-release-tool verify-release KEY_DIR DOCUMENT SIGNATURE\n  \
         punar-release-tool verify-channel KEY_DIR DOCUMENT SIGNATURE\n  \
         punar-release-tool verify-artifact FILE SHA256 SIZE"
    );
    std::process::exit(2);
}

fn signing_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read signing seed: {error}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "signing seed must contain exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {what}: {error}"))
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_, command, seed, output] if command == "public-key" => {
            let key = signing_key(Path::new(seed))?;
            fs::write(output, key.verifying_key().to_bytes())
                .map_err(|error| format!("cannot write public key: {error}"))?;
        }
        [_, command, seed, document, signature] if command == "sign" => {
            let key = signing_key(Path::new(seed))?;
            let document = read(Path::new(document), "document")?;
            fs::write(signature, key.sign(&document).to_bytes())
                .map_err(|error| format!("cannot write detached signature: {error}"))?;
        }
        [_, command, key_dir, document, signature]
            if command == "verify-release" || command == "verify-channel" =>
        {
            let keys =
                ReleaseKeySet::load_dir(Path::new(key_dir)).map_err(|error| error.to_string())?;
            let document = read(Path::new(document), "document")?;
            let signature = read(Path::new(signature), "signature")?;
            if command == "verify-release" {
                verify_release_manifest(&document, &signature, &keys)
                    .map_err(|error| error.to_string())?;
            } else {
                verify_channel_metadata(&document, &signature, &keys)
                    .map_err(|error| error.to_string())?;
            }
        }
        [_, command, artifact, digest, size] if command == "verify-artifact" => {
            let expected_size = size
                .parse::<u64>()
                .map_err(|_| "artifact size must be an unsigned integer".to_string())?;
            let artifact = fs::File::open(artifact)
                .map_err(|error| format!("cannot open artifact: {error}"))?;
            verify_reader(artifact, digest, expected_size).map_err(|error| error.to_string())?;
        }
        _ => usage(),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("PUNAR_RELEASE_TOOL_ERROR: {error}");
        std::process::exit(1);
    }
}
