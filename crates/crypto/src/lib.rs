use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ad: &[u8],
    data: &mut [u8],
) -> [u8; TAG_SIZE] {
    assert!(
        data.len() <= usize::MAX,
        "Plaintext exceeds XChaCha20Poly1305 maximum size"
    );
    assert!(
        (ad.len() as u128) <= u64::MAX as u128,
        "AAD exceeds XChaCha20Poly1305 maximum size"
    );

    let tag = XChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(nonce.into(), ad, data.into())
        .unwrap();

    assert!(tag.len() == TAG_SIZE, "Tag size is incorrect (not 16)");

    let mut tag_raw = [0u8; TAG_SIZE];
    tag_raw.clone_from_slice(&tag);

    tag_raw
}

pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ad: &[u8],
    tag: &[u8; TAG_SIZE],
    data: &mut [u8],
) -> Result<(), chacha20poly1305::Error> {
    assert!(
        data.len() <= usize::MAX,
        "Plaintext exceeds XChaCha20Poly1305 maximum size"
    );
    assert!(
        (ad.len() as u128) <= u64::MAX as u128,
        "AAD exceeds XChaCha20Poly1305 maximum size"
    );

    XChaCha20Poly1305::new(key.into()).decrypt_inout_detached(
        nonce.into(),
        ad,
        data.into(),
        tag.into(),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut pt = *b"Hello, world!";
        let key = [0u8; KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];

        let tag = encrypt(&key, &nonce, b"", &mut pt);
        decrypt(&key, &nonce, b"", &tag, &mut pt).unwrap();

        assert_eq!(&pt, b"Hello, world!");
    }
}
