// Compile-time string obfuscation. Literals passed through `obf!` never land
// in the binary in plaintext: the const evaluator XORs them, and only the
// encoded bytes are emitted. Decoding happens on the stack at use time.

pub const KEY: &[u8] = b"m3t4-4080-nest";

pub const fn enc<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[i] ^ KEY[i % KEY.len()];
        i += 1;
    }
    out
}

pub fn dec(bytes: &[u8]) -> String {
    let plain: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ KEY[i % KEY.len()])
        .collect();
    String::from_utf8(plain).unwrap_or_default()
}

#[macro_export]
macro_rules! obf {
    ($s:literal) => {{
        const N: usize = $s.len();
        const E: [u8; N] = $crate::obf::enc::<N>($s.as_bytes());
        // black_box stops LLVM from folding enc+dec back into the literal.
        $crate::obf::dec(std::hint::black_box(&E))
    }};
}
