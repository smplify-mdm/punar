//! SHA-256 (FIPS 180-4), in safe Rust, ~70 lines.
//!
//! # Why a third copy rather than a shared crate
//!
//! This is the third hand-rolled copy in the workspace
//! (`punard::util::sha256_hex`, `punar_secrets::sha256`), and it is
//! deliberate on the precedent both of those wrote down and that
//! `punar-agentd`'s own `crate::util` states in full: two daemons with
//! separate lifetimes copy four short functions rather than widen
//! `punar-common`, which is a **contract** crate and not a utility
//! shelf. Pulling `sha2` + `digest` + `generic-array` + `typenum` into
//! the image to hash two short strings per detection would widen the
//! supply chain for one function, against the dependency posture the
//! workspace states for `chrono`/`time` and re-states for the broker.
//! Correctness is pinned against the FIPS 180-4 vectors below, exactly
//! as the other two copies are.
//!
//! # Honest scope
//!
//! Detection identities are **not** security tokens. Nothing
//! authenticates on a `detection_id` or a `signature_id`; they are
//! collision-resistant names for "one running process" and "one thing
//! seen" (milestone-10.md section 4), and their whole security property
//! is that a hash can appear in an exported inventory answer without
//! leaking the path it was computed from. This is not constant-time and
//! does not need to be: every input is already visible in `/proc` to the
//! user who owns the process.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    hex
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding: 0x80, zeros, then the 64-bit big-endian bit length.
    let mut message = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 / NIST CAVP known-answer vectors — the same three the
    /// other two copies in this workspace are pinned against, so a
    /// divergence between the copies is a test failure and not a
    /// surprise in production.
    #[test]
    fn matches_the_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Length-block boundaries: 55/56/63/64 bytes are where a padding
    /// bug hides.
    #[test]
    fn block_boundaries_are_padded_correctly() {
        for len in [55usize, 56, 63, 64, 65] {
            let digest = sha256_hex(&vec![b'x'; len]);
            assert_eq!(digest.len(), 64, "len {len}");
            assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        }
        // Distinct inputs across a block boundary give distinct digests.
        assert_ne!(sha256_hex(&[b'x'; 55]), sha256_hex(&[b'x'; 56]));
    }
}
