/// Pads a buffer containing a 4-byte length prefix
/// followed by `data_size` bytes of actual data.
///
/// Assumes data already occupies buf[4..4 + data_size].
pub fn pad_data(buf: &mut [u8], data_size: usize) {
    assert!(data_size <= u32::MAX as usize, "Data too large");
    assert!(buf.len() >= data_size + 4, "Buffer too small");

    buf[..4].copy_from_slice(&(data_size as u32).to_le_bytes());

    buf[4 + data_size..].fill(0);
}

/// Unpads a buffer containing a 4-byte length prefix
///
/// Assumes padded data already occupies buf[4..]
pub fn unpad_data(buf: &[u8]) -> Option<&[u8]> {
    assert!(buf.len() >= 4);

    let mut length_bytes = [0u8; 4];
    length_bytes.clone_from_slice(&buf[..4]);
    let length = u32::from_le_bytes(length_bytes) as usize;

    if length <= buf.len() - 4 {
        Some(&buf[4..4 + length])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad() {
        let data = b"Hello, world!";
        let mut buffer = [0u8; 100];
        buffer[4..4 + data.len()].clone_from_slice(data);
        pad_data(&mut buffer, data.len());

        let unpadded = unpad_data(&buffer).unwrap();

        assert_eq!(data, unpadded, "Unpadded data is not the same as padded");
    }
}
