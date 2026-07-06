pub type B3 = [u8; 32];

pub fn b3(bytes: impl AsRef<[u8]>) -> B3 {
    *blake3::hash(bytes.as_ref()).as_bytes()
}

pub fn combine(tag: &str, chunks: &[&[u8]]) -> B3 {
    let mut h = blake3::Hasher::new();
    h.update(tag.as_bytes());
    for c in chunks {
        h.update(&(c.len() as u64).to_le_bytes());
        h.update(c);
    }
    *h.finalize().as_bytes()
}
