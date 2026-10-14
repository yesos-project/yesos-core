//! ==============================================================================
//! YesOS 2.0 - Cryptographic primitives exported to the C kernel
//!
//! All algorithms come from the audited RustCrypto crates; nothing here is
//! hand-rolled crypto. This module only adapts them to a C ABI:
//!   - XChaCha20-Poly1305 AEAD (vault file encryption, key wrapping)
//!   - Argon2id (passphrase / password / PIN key derivation)
//!   - ChaCha20 DRBG with fast key erasure (nonces, salts, keys)
//!   - BLAKE2b (entropy pool mixing)
//! ==============================================================================

use core::cell::UnsafeCell;
use core::slice;
use core::sync::atomic::{AtomicBool, Ordering};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use blake2::{Blake2b512, Digest};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

pub const YC_OK: i32 = 0;
pub const YC_ERR_PARAM: i32 = -1;
pub const YC_ERR_AUTH: i32 = -2;
pub const YC_ERR_BUSY: i32 = -3;
pub const YC_ERR_KDF: i32 = -4;
pub const YC_ERR_NO_ENTROPY: i32 = -5;

/// Argon2id memory budget (KiB). 8 MiB keeps unlock under ~1 s on an SBC
/// while still forcing GPU/ASIC attackers to pay for memory per guess.
pub const YC_ARGON2_M_KIB: u32 = 8 * 1024;
pub const YC_ARGON2_T_COST: u32 = 3;
pub const YC_ARGON2_P_COST: u32 = 1;

/// Minimal spinlock-protected cell: the kernel has several harts and no OS
/// mutex, so shared crypto state is guarded with an atomic flag.
pub struct Locked<T> {
    busy: AtomicBool,
    value: UnsafeCell<T>,
}

unsafe impl<T> Sync for Locked<T> {}

impl<T> Locked<T> {
    pub const fn new(value: T) -> Self {
        Self { busy: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self
            .busy
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let r = f(unsafe { &mut *self.value.get() });
        self.busy.store(false, Ordering::Release);
        r
    }

    pub fn try_with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let r = f(unsafe { &mut *self.value.get() });
        self.busy.store(false, Ordering::Release);
        Some(r)
    }
}

// -----------------------------------------------------------------------------
// DRBG: ChaCha20 keystream with fast key erasure, reseeded through BLAKE2b
// -----------------------------------------------------------------------------

struct Drbg {
    key: [u8; 32],
    entropy_bits: u32,
}

static DRBG: Locked<Drbg> = Locked::new(Drbg { key: [0; 32], entropy_bits: 0 });

/// Mixes `len` bytes of seed material into the pool. `entropy_bits` is the
/// caller's conservative estimate of real entropy contained in the material.
#[no_mangle]
pub extern "C" fn yc_rng_mix(material: *const u8, len: usize, entropy_bits: u32) {
    if material.is_null() || len == 0 {
        return;
    }
    let input = unsafe { slice::from_raw_parts(material, len) };
    DRBG.with(|d| {
        let mut h = Blake2b512::new();
        h.update(b"YesOS-DRBG-reseed-v1");
        h.update(d.key);
        h.update(input);
        let mut out = h.finalize();
        d.key.copy_from_slice(&out[..32]);
        out.as_mut_slice().zeroize();
        d.entropy_bits = d.entropy_bits.saturating_add(entropy_bits);
    });
}

/// Returns the accumulated entropy estimate (bits) of the pool.
#[no_mangle]
pub extern "C" fn yc_rng_entropy_bits() -> u32 {
    DRBG.with(|d| d.entropy_bits)
}

pub fn rng_fill(out: &mut [u8]) -> i32 {
    DRBG.with(|d| {
        if d.entropy_bits < 128 {
            return YC_ERR_NO_ENTROPY;
        }
        // Each request uses a fresh key; the first 32 bytes of keystream
        // become the next key so past outputs cannot be reconstructed.
        let mut cipher = ChaCha20::new(&d.key.into(), &[0u8; 12].into());
        let mut next = [0u8; 32];
        cipher.apply_keystream(&mut next);
        out.fill(0);
        cipher.apply_keystream(out);
        d.key = next;
        next.zeroize();
        YC_OK
    })
}

/// Fills `out` with `len` cryptographically secure random bytes.
/// Fails with YC_ERR_NO_ENTROPY until at least 128 bits have been mixed in.
#[no_mangle]
pub extern "C" fn yc_rng_fill(out: *mut u8, len: usize) -> i32 {
    if out.is_null() {
        return YC_ERR_PARAM;
    }
    rng_fill(unsafe { slice::from_raw_parts_mut(out, len) })
}

// -----------------------------------------------------------------------------
// Argon2id
// -----------------------------------------------------------------------------

const ARGON2_BLOCKS: usize = YC_ARGON2_M_KIB as usize;
static ARGON2_MEM: Locked<[Block; ARGON2_BLOCKS]> = Locked::new([const { Block::new() }; ARGON2_BLOCKS]);

/// Derives `out_len` bytes from a password and salt with Argon2id using the
/// kernel-wide cost parameters. Returns YC_ERR_BUSY if another hart is
/// currently running a derivation (callers retry or report failure).
#[no_mangle]
pub extern "C" fn yc_argon2id(
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if (pw.is_null() && pw_len != 0) || salt.is_null() || out.is_null() || salt_len < 16 || out_len < 16 {
        return YC_ERR_PARAM;
    }
    let pw = if pw_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(pw, pw_len) } };
    let salt = unsafe { slice::from_raw_parts(salt, salt_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };

    let params = match Params::new(YC_ARGON2_M_KIB, YC_ARGON2_T_COST, YC_ARGON2_P_COST, Some(out_len)) {
        Ok(p) => p,
        Err(_) => return YC_ERR_KDF,
    };
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    ARGON2_MEM
        .try_with(|mem| {
            let r = argon.hash_password_into_with_memory(pw, salt, out, &mut mem[..]);
            for b in mem.iter_mut() {
                *b = Block::new();
            }
            if r.is_ok() { YC_OK } else { YC_ERR_KDF }
        })
        .unwrap_or(YC_ERR_BUSY)
}

/// Argon2id with caller-provided working memory (`mem_len` >= YC_ARGON2_M_KIB
/// KiB, 64-byte aligned). Used by the key hart, whose memory lives in a PMP
/// region no other hart can access. The memory is wiped before returning.
#[no_mangle]
pub extern "C" fn yc_argon2id_with_memory(
    pw: *const u8,
    pw_len: usize,
    salt: *const u8,
    salt_len: usize,
    out: *mut u8,
    out_len: usize,
    mem: *mut u8,
    mem_len: usize,
) -> i32 {
    if (pw.is_null() && pw_len != 0) || salt.is_null() || out.is_null() || salt_len < 16 || out_len < 16
        || mem.is_null() || (mem as usize) % 64 != 0 || mem_len < ARGON2_BLOCKS * Block::SIZE
    {
        return YC_ERR_PARAM;
    }
    let pw = if pw_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(pw, pw_len) } };
    let salt = unsafe { slice::from_raw_parts(salt, salt_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    let blocks = unsafe { slice::from_raw_parts_mut(mem as *mut Block, ARGON2_BLOCKS) };

    let params = match Params::new(YC_ARGON2_M_KIB, YC_ARGON2_T_COST, YC_ARGON2_P_COST, Some(out_len)) {
        Ok(p) => p,
        Err(_) => return YC_ERR_KDF,
    };
    let r = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pw, salt, out, &mut blocks[..]);
    for b in blocks.iter_mut() {
        *b = Block::new();
    }
    if r.is_ok() { YC_OK } else { YC_ERR_KDF }
}

// -----------------------------------------------------------------------------
// XChaCha20-Poly1305 (detached tag, in place)
// -----------------------------------------------------------------------------

/// Encrypts `buf` in place and writes the 16-byte tag to `tag_out`.
#[no_mangle]
pub extern "C" fn yc_aead_seal(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    buf: *mut u8,
    len: usize,
    tag_out: *mut u8,
) -> i32 {
    if key.is_null() || nonce.is_null() || tag_out.is_null() || (buf.is_null() && len != 0) || (aad.is_null() && aad_len != 0) {
        return YC_ERR_PARAM;
    }
    let key = unsafe { slice::from_raw_parts(key, 32) };
    let nonce = XNonce::from_slice(unsafe { slice::from_raw_parts(nonce, 24) });
    let aad = if aad_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(aad, aad_len) } };
    let buf = if len == 0 { &mut [][..] } else { unsafe { slice::from_raw_parts_mut(buf, len) } };

    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return YC_ERR_PARAM,
    };
    match cipher.encrypt_in_place_detached(nonce, aad, buf) {
        Ok(tag) => {
            unsafe { slice::from_raw_parts_mut(tag_out, 16) }.copy_from_slice(&tag);
            YC_OK
        }
        Err(_) => YC_ERR_PARAM,
    }
}

/// Verifies the tag and decrypts `buf` in place. On authentication failure
/// the buffer is zeroed and YC_ERR_AUTH is returned.
#[no_mangle]
pub extern "C" fn yc_aead_open(
    key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    buf: *mut u8,
    len: usize,
    tag: *const u8,
) -> i32 {
    if key.is_null() || nonce.is_null() || tag.is_null() || (buf.is_null() && len != 0) || (aad.is_null() && aad_len != 0) {
        return YC_ERR_PARAM;
    }
    let key = unsafe { slice::from_raw_parts(key, 32) };
    let nonce = XNonce::from_slice(unsafe { slice::from_raw_parts(nonce, 24) });
    let aad = if aad_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(aad, aad_len) } };
    let buf = if len == 0 { &mut [][..] } else { unsafe { slice::from_raw_parts_mut(buf, len) } };
    let tag = Tag::from_slice(unsafe { slice::from_raw_parts(tag, 16) });

    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => return YC_ERR_PARAM,
    };
    match cipher.decrypt_in_place_detached(nonce, aad, buf, tag) {
        Ok(()) => YC_OK,
        Err(_) => {
            buf.zeroize();
            YC_ERR_AUTH
        }
    }
}

// -----------------------------------------------------------------------------
// Poly1305 for the register-resident XChaCha20 path (key hart)
// -----------------------------------------------------------------------------

/// RFC 8439 AEAD tag: Poly1305(otk, aad || pad16 || ct || pad16 || le64(aad_len) || le64(ct_len)).
/// `otk` is the one-time key (first 32 bytes of ChaCha20 block 0).
#[no_mangle]
pub extern "C" fn yc_poly1305_aead_tag(
    otk: *const u8,
    aad: *const u8,
    aad_len: usize,
    ct: *const u8,
    ct_len: usize,
    tag_out: *mut u8,
) -> i32 {
    use poly1305::universal_hash::{KeyInit as _, UniversalHash};
    use poly1305::{Block as PolyBlock, Poly1305};
    if otk.is_null() || tag_out.is_null() || (aad.is_null() && aad_len != 0) || (ct.is_null() && ct_len != 0) {
        return YC_ERR_PARAM;
    }
    let key = unsafe { slice::from_raw_parts(otk, 32) };
    let aad = if aad_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(aad, aad_len) } };
    let ct = if ct_len == 0 { &[][..] } else { unsafe { slice::from_raw_parts(ct, ct_len) } };
    let mut mac = match Poly1305::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return YC_ERR_PARAM,
    };
    mac.update_padded(aad);
    mac.update_padded(ct);
    let mut lens = PolyBlock::default();
    lens[..8].copy_from_slice(&(aad_len as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ct_len as u64).to_le_bytes());
    mac.update(&[lens]);
    let tag = mac.finalize();
    unsafe { slice::from_raw_parts_mut(tag_out, 16) }.copy_from_slice(&tag);
    YC_OK
}

// -----------------------------------------------------------------------------
// BLAKE2b-256: kernel image hash and keyed integrity MAC (key hart)
// -----------------------------------------------------------------------------

/// Unkeyed BLAKE2b-256 over two consecutive ranges (kernel .text then .rodata).
#[no_mangle]
pub extern "C" fn yc_blake2b256_2(a: *const u8, a_len: usize, b: *const u8, b_len: usize, out: *mut u8) -> i32 {
    use blake2::digest::consts::U32;
    use blake2::Blake2b;
    if out.is_null() || (a.is_null() && a_len != 0) || (b.is_null() && b_len != 0) {
        return YC_ERR_PARAM;
    }
    let mut h = Blake2b::<U32>::new();
    if a_len != 0 {
        h.update(unsafe { slice::from_raw_parts(a, a_len) });
    }
    if b_len != 0 {
        h.update(unsafe { slice::from_raw_parts(b, b_len) });
    }
    unsafe { slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&h.finalize());
    YC_OK
}

/// Keyed BLAKE2b-256 (RFC 7693 keyed mode) of le64(index) || data.
/// The index binds each MAC to its chunk position.
#[no_mangle]
pub extern "C" fn yc_blake2b256_mac(key: *const u8, index: u64, data: *const u8, len: usize, out: *mut u8) -> i32 {
    use blake2::digest::consts::U32;
    use blake2::digest::Mac;
    use blake2::Blake2bMac;
    if key.is_null() || out.is_null() || (data.is_null() && len != 0) {
        return YC_ERR_PARAM;
    }
    let key = unsafe { slice::from_raw_parts(key, 32) };
    let mut m = match Blake2bMac::<U32>::new_with_salt_and_personal(key, &[], b"YesOSint") {
        Ok(m) => m,
        Err(_) => return YC_ERR_PARAM,
    };
    Mac::update(&mut m, &index.to_le_bytes());
    if len != 0 {
        Mac::update(&mut m, unsafe { slice::from_raw_parts(data, len) });
    }
    unsafe { slice::from_raw_parts_mut(out, 32) }.copy_from_slice(&m.finalize().into_bytes());
    YC_OK
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Constant-time comparison. Returns 1 if equal, 0 otherwise.
#[no_mangle]
pub extern "C" fn yc_ct_eq(a: *const u8, b: *const u8, len: usize) -> i32 {
    if a.is_null() || b.is_null() {
        return 0;
    }
    let a = unsafe { slice::from_raw_parts(a, len) };
    let b = unsafe { slice::from_raw_parts(b, len) };
    let mut diff = 0u8;
    for i in 0..len {
        diff |= a[i] ^ b[i];
    }
    (core::hint::black_box(diff) == 0) as i32
}

/// Zeroes memory in a way the optimizer cannot elide.
#[no_mangle]
pub extern "C" fn yc_wipe(p: *mut u8, len: usize) {
    if !p.is_null() && len != 0 {
        unsafe { slice::from_raw_parts_mut(p, len) }.zeroize();
    }
}
