use crate::util::xtime;

/// Rijndael S-box lookup table
pub const S_BOX: [u8; 256] = generate_sbox();

/// Inverse of the Rijndael S-box lookup table
pub const S_BOX_INVERSE: [u8; 256] = generate_sbox_inverse(S_BOX);

/// Rcon lookup table for key expansion
pub const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// Performs a left rotation on a byte
#[inline]
const fn rotl8(x: u8, shift: u8) -> u8 {
    (x << shift) | (x >> (8 - shift))
}

/// Generates the Rijndael S-box lookup table
const fn generate_sbox() -> [u8; 256] {
    // Adapted from Wikipedia: https://en.wikipedia.org/wiki/Rijndael_S-box
    let mut sbox = [0u8; 256];

    sbox[0] = 0x63;

    let mut p: u8 = 1;
    let mut q: u8 = 1;

    loop {
        p ^= xtime(p);

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if q & 0x80 != 0 { 0x09 } else { 0 };

        let xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);

        sbox[p as usize] = xformed ^ 0x63;

        if p == 1 {
            break;
        }
    }

    sbox
}

/// Generates the inverse of the Rijndael S-box lookup table
const fn generate_sbox_inverse(sbox: [u8; 256]) -> [u8; 256] {
    let mut inverse = [0u8; 256];

    let mut i = 0;

    while i < 256 {
        inverse[sbox[i] as usize] = i as u8;
        i += 1;
    }

    inverse
}
