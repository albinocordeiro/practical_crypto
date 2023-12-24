//! Implement the SHA-256 hashing algorithm
use itertools::{Itertools, izip};

/// Constant value used for iteration t of the hash computation
pub const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pads an input message following the SHA-256 requirement.
///
/// The function applies the padding required by the SHA-256 algorithm to the input message.
/// The padding consists of a single 1 bit, followed by zero or more 0 bits, followed by the message length.
/// The padded message's total length (in bits) will always be a multiple of 512.
///
/// # Arguments
///
/// * `message` - A byte slice that holds the original message to be padded.
///
/// # Returns
///
/// This function returns a vector of bytes that represents the padded message.
///
/// # Panics
///
/// This function should not panic under normal operation. However, as it uses standard library functions like `Vec::push` and `Vec::extend_from_slice`,
/// it may panic if these functions panic (e.g. in case of out-of-memory conditions).
///
pub fn pad_message(message: &[u8]) -> Vec<u8> {
    let mut padded_message = message.to_vec();
    padded_message.push(0x80);
    while padded_message.len() % 64 != 56 {
        padded_message.push(0x00);
    }
    // Add length of message
    let msg_len = ((message.len()*8) as u64).to_be_bytes();
    padded_message.extend_from_slice(&msg_len);
    padded_message
}

/// Computes the SHA256 checksum of a given input.
///
/// # Arguments
///
/// * `message` - A byte slice that holds the data for which we need the SHA256 hash.
///
/// # Returns
///
/// * A 32-byte array representing the SHA256 hash of the input data.
///
/// # Panics
///
/// The function can panic if the internal function calls or operations fail.
///
pub fn sha256(message: &[u8]) -> Vec<u8> {
    let padded_message = pad_message(message);

    // initialize H for sha 256
    let mut hash: [u32; 8] = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];

    // Prepare message schedule
    let mut message_schedule = [0u32; 64];
    for block in padded_message.chunks_exact(64) {
        for (w, m) in izip!(&mut message_schedule[..16], block.chunks_exact(4)) {
            *w = u32::from_be_bytes(m.try_into().unwrap());
        }

        for t in  16..64 {
            message_schedule[t] = sigma1(message_schedule[t-2]).wrapping_add( message_schedule[t-7]).wrapping_add(sigma0(message_schedule[t - 15])).wrapping_add( message_schedule[t - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        K32.into_iter().zip(message_schedule).for_each(|(k, w)|{
            let t1 = h.wrapping_add(sigma_1_256(e)).wrapping_add(ch(e, f, g)).wrapping_add(k).wrapping_add(w);
            let t2 = sigma_0_256(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        });
        for (hsh, update) in izip!(&mut hash, &[a, b, c, d, e, f, g, h]) {
            *hsh = update.wrapping_add(*hsh);
        }
    }
    hash.iter().fold(Vec::<u8>::new(), |mut acc, item|{
        acc.extend_from_slice(item.to_be_bytes().as_slice());
        acc
    })
}

#[inline(always)]
fn sigma_1_256(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
#[inline(always)]
fn sigma_0_256(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}
#[inline(always)]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right( 19) ^ (x>>10)
}
#[inline(always)]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x>>3)
}

#[cfg(test)]
mod tests {
    use crate::sha256::{pad_message, sha256};
    use sha2::{Sha256, Digest};
    use hex;
    #[test]
    fn test_padding_no_additional_block() {
        let message = b"This is a short message";
        let padded_message = pad_message(message);

        // The message is less than 56 bytes, so it should fit within one 64-byte block
        assert_eq!(padded_message.len(), 64);

        // The last 8 bytes should be the length of the original message in bits
        let original_len_bits = (message.len() as u64) * 8;
        assert_eq!(padded_message[56..], original_len_bits.to_be_bytes());
    }

    #[test]
    fn test_padding_additional_block() {
        // Create a message of 57 bytes (one byte too large for a single block)
        let message = b"This message is exactly long enough to need another block";
        let padded_message = pad_message(message);

        // There should be two 64-byte blocks
        assert_eq!(padded_message.len(), 128);

        // The last 8 bytes should be the length of the original message in bits
        let original_len_bits = (message.len() as u64) * 8;
        assert_eq!(padded_message[120..], original_len_bits.to_be_bytes());
    }

    #[test]
    fn test_sha256() {
        let input = b"hello, world";
        let mut hasher = Sha256::new();
        hasher.update(input);
        let expected = hasher.finalize().to_vec();
        println!("{expected:?}");
        let actual = sha256(input);
        let actual = actual.iter().fold(Vec::<u8>::new(), |mut a, b|{
            a.extend_from_slice(&b.to_be_bytes().to_vec());
            a
        });

        println!("actual len: {}\nexpected len: {}", actual.len(), expected.as_slice().len());
        assert_eq!(actual, expected.as_slice());
    }

    #[test]
    fn test_sha256_known_hashes() {
        let tests : [( &[u8], &[u8]); 4] = [
            (b"",      &hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap()),
            (b"abc",   &hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap()),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", &hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").unwrap()),
            (b"a", &hex::decode("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb").unwrap()),
        ];

        for (msg, expected) in &tests {
            assert_eq!(&sha256(msg), expected, "{msg:?}");
        }
    }
}

