//! Implementation of the AES block cipher for keys of size 128 bits.
//! The state which can be thought as a 4x4 matrix of u8 (byte) values will be represented as a [u8; 16] row-major
//! The input and output blocks will be represented as [u8; 16] column-major

use std::fs::File;
use std::io::{Read, Write, Seek, SeekFrom};
use log::info;
use crate::consts::{INVERSE_S_BOX, NB, NK, NR, RCON, S_BOX, STATE_SIZE, TIMES_11, TIMES_13, TIMES_14, TIMES_2, TIMES_3, TIMES_9, WORD_SIZE};

fn s_box(input: u8) -> u8 {
    let (a, b) = (input >> 4, input & 0x0f);
    S_BOX[(a * 16 + b) as usize]
}

fn sub_bytes(input: &mut [u8]) {
    input.iter_mut().for_each(|x| *x = s_box(*x));
}

fn shift_rows(state: &mut [u8; STATE_SIZE]) {
    state[NB..2 * NB].rotate_left(1);
    state[2 * NB..3 * NB].rotate_left(2);
    state[3 * NB..4 * NB].rotate_left(3);
}

fn mix_columns(state: &mut [u8; STATE_SIZE]) {
    for c in 0..NB {
        let s0c = state[c];
        let s1c = state[NB + c];
        let s2c = state[2 * NB + c];
        let s3c = state[3 * NB + c];

        state[c] = TIMES_2[s0c as usize] ^ TIMES_3[s1c as usize] ^ s2c ^ s3c;
        state[NB + c] = s0c ^ TIMES_2[s1c as usize] ^ TIMES_3[s2c as usize] ^ s3c;
        state[2 * NB + c] = s0c ^ s1c ^ TIMES_2[s2c as usize] ^ TIMES_3[s3c as usize];
        state[3 * NB + c] = TIMES_3[s0c as usize] ^ s1c ^ s2c ^ TIMES_2[s3c as usize];
    }
}

fn add_round_key(state: &mut [u8; STATE_SIZE], key_schedule: &[[u8; 4]; NK * (NR + 1)], round: usize) {
    for c in 0..NB {
        state[c] ^= key_schedule[round * NB + c][0];
        state[NB + c] ^= key_schedule[round * NB + c][1];
        state[2 * NB + c] ^= key_schedule[round * NB + c][2];
        state[3 * NB + c] ^= key_schedule[round * NB + c][3];
    }
}

fn sub_word(input: &mut [u8; 4]) {
    input.iter_mut().for_each(|x| *x = s_box(*x));
}

fn rot_word(input: &mut [u8; 4]) {
    input.rotate_left(1);
}

pub fn key_expansion(key: &[u8; WORD_SIZE * NK]) -> [[u8; 4]; NK * (NR + 1)] {
    let mut w = [[0u8; WORD_SIZE]; NK * (NR + 1)];
    let mut temp = [0u8; WORD_SIZE];

    for c in 0..NK {
        w[c][0] = key[c * 4];
        w[c][1] = key[1 + c * 4];
        w[c][2] = key[2 + c * 4];
        w[c][3] = key[3 + c * 4];
    }

    for c in NK..(NK * (NR + 1)) {
        temp.copy_from_slice(&w[c - 1]);
        if c % NK == 0 {
            rot_word(&mut temp);
            sub_word(&mut temp);
            temp[0] ^= RCON[c / NK];
        } else if NK > 6 && c % NK == 4 {
            sub_word(&mut temp);
        }
        for i in 0..WORD_SIZE {
            w[c][i] = w[c - NK][i] ^ temp[i];
        }
    }

    w
}

fn into_column_major(state: &[u8; STATE_SIZE]) -> [u8; STATE_SIZE] {
    let mut output = [0; STATE_SIZE];
    for c in 0..NB {
        for r in 0..NB {
            output[c * NB + r] = state[r * NB + c];
        }
    }
    output
}

fn into_row_major(state: &[u8; STATE_SIZE]) -> [u8; STATE_SIZE] {
    let mut output = [0; STATE_SIZE];
    for r in 0..NB {
        for c in 0..NB {
            output[r * NB + c] = state[c * NB + r];
        }
    }
    output
}

fn cypher(input_block: &[u8; STATE_SIZE], key_schedule: &[[u8; 4]; NK * (NR + 1)]) -> [u8; STATE_SIZE] {
    let mut state = into_column_major(input_block);
    add_round_key(&mut state, key_schedule, 0);
    for round in 1..NR {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, key_schedule, round);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, key_schedule, NR);
    into_row_major(&state)
}

fn inv_shift_rows(state: &mut [u8; STATE_SIZE]) {
    state[NB..2 * NB].rotate_left(3);
    state[2 * NB..3 * NB].rotate_left(2);
    state[3 * NB..4 * NB].rotate_left(1);
}

fn inv_s_box(input: u8) -> u8 {
    let (a, b) = (input >> 4, input & 0x0f);
    INVERSE_S_BOX[(a * 16 + b) as usize]
}

fn inv_sub_bytes(state: &mut [u8; STATE_SIZE]) {
    state.iter_mut().for_each(|x| *x = inv_s_box(*x));
}

fn inv_mix_columns(state: &mut [u8; STATE_SIZE]) {
    for c in 0..NB {
        let s0c = state[c];
        let s1c = state[NB + c];
        let s2c = state[2 * NB + c];
        let s3c = state[3 * NB + c];

        state[c] = TIMES_14[s0c as usize] ^ TIMES_11[s1c as usize] ^ TIMES_13[s2c as usize] ^ TIMES_9[s3c as usize];
        state[NB + c] = TIMES_9[s0c as usize] ^ TIMES_14[s1c as usize] ^ TIMES_11[s2c as usize] ^ TIMES_13[s3c as usize];
        state[2 * NB + c] = TIMES_13[s0c as usize] ^ TIMES_9[s1c as usize] ^ TIMES_14[s2c as usize] ^ TIMES_11[s3c as usize];
        state[3 * NB + c] = TIMES_11[s0c as usize] ^ TIMES_13[s1c as usize] ^ TIMES_9[s2c as usize] ^ TIMES_14[s3c as usize];
    }
}

fn inv_cypher(input_block: &[u8; STATE_SIZE], key_schedule: &[[u8; 4]; NK * (NR + 1)]) -> [u8; STATE_SIZE] {
    let mut state = into_column_major(input_block);
    add_round_key(&mut state, key_schedule, NR);
    for round in (1..NR).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, key_schedule, round);
        inv_mix_columns(&mut state);
    }
    inv_sub_bytes(&mut state);
    inv_shift_rows(&mut state);
    add_round_key(&mut state, key_schedule, 0);
    into_row_major(&state)
}

fn read_key(key_file: &str) -> anyhow::Result<[u8; 16]> {
    let mut file = File::open(key_file)?;
    let mut buffer = [0; 16];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Encrypts a file using AES-128
/// Reads the file in blocks of 16 bytes and encrypts each block
/// Writes the encrypted blocks to the output file
pub fn encrypt_file(input_file: &str, output_file: &str, key_file: &str) -> anyhow::Result<()> {
    let key = read_key(key_file)?;
    let key_schedule = key_expansion(&key);
    // Read a block at a time from the input file
    let mut input = File::open(input_file)?;
    let mut output = File::create(output_file)?;
    let mut buffer = [0; STATE_SIZE];
    loop {
        let bytes_read = input.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        if bytes_read < STATE_SIZE { // Pad the last block with PKCS#7 padding
            buffer[bytes_read..].iter_mut().for_each(|x| *x = (STATE_SIZE - bytes_read) as u8);
        }
        let encrypted_block = cypher(&buffer, &key_schedule);
        output.write(&encrypted_block)?;
    }
    output.flush()?;
    Ok(())
}

/// Decrypts a file using AES-128
/// Reads the file in blocks of 16 bytes and decrypts each block
/// Writes the decrypted blocks to the output file
pub fn decrypt_file(input_file: &str, output_file: &str, key_file: &str) -> anyhow::Result<()> {
    let key = read_key(key_file)?;
    let key_schedule = key_expansion(&key);
    // Read a block at a time from the input file
    let mut input = File::open(input_file)?;
    let mut input_len = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;
    info!("File length: {} bytes", input_len);
    let mut output = File::create(output_file)?;
    let mut buffer = [0; STATE_SIZE];
    
    loop {
        let bytes_read = input.read(&mut buffer)?;

        let decrypted_block = inv_cypher(&buffer, &key_schedule);
        if input_len as usize == STATE_SIZE { // last block
            // PKS#7 remove the padding from the last block
            let padding_start = decrypted_block.iter().enumerate().find(|(x, byte)| (**byte == (STATE_SIZE - *x) as u8) && decrypted_block[*x..].iter().all(|b| *b == **byte));
            if let Some((padding_start, _)) = padding_start {
                output.write(&decrypted_block[..padding_start])?;
            } else {
                output.write(&decrypted_block)?;
            }
            break;
        }
        input_len -= bytes_read as u64;
        output.write(&decrypted_block)?;
    }
    output.flush()?;
    Ok(())
}

// unit tests
#[cfg(test)]
mod tests {
    use std::fs::File;
    use anyhow::Result;
    use super::*;

    #[test]
    fn test_s_box() {
        assert_eq!(s_box(0x00), 0x63);
        assert_eq!(s_box(0x0f), 0x76);
        assert_eq!(s_box(0x53), 0xed);
    }

    #[test]
    fn test_sub_bytes() {
        let mut input = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        sub_bytes(&mut input);
        assert_eq!(input, [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]);
    }

    #[test]
    fn test_shift_rows() {
        let mut input = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        shift_rows(&mut input);
        assert_eq!(input, [0x00, 0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x04, 0x0a, 0x0b, 0x08, 0x09, 0x0f, 0x0c, 0x0d, 0x0e]);
    }

    #[test]
    fn test_mix_columns() {
        let rows = [0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6];
        let mut input = into_column_major(&rows);
        mix_columns(&mut input);
        let output = into_row_major(&input);
        assert_eq!(output, [0x8e, 0x4d, 0xa1, 0xbc, 0x9f, 0xdc, 0x58, 0x9d, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6]);
    }

    #[test]
    fn test_rot_word() {
        let original: [u8; 4] = [0x09, 0xcf, 0x4f, 0x3c];
        let mut rotated = original;
        rot_word(&mut rotated);
        assert_eq!(rotated, [0xcf, 0x4f, 0x3c, 0x09]);
    }

    #[test]
    fn test_sub_word() {
        let original: [u8; 4] = [0xcf, 0x4f, 0x3c, 0x09];
        let mut subbed = original;
        sub_word(&mut subbed);
        assert_eq!(subbed, [0x8a, 0x84, 0xeb, 0x01]);
        subbed[0] ^= RCON[1];
        assert_eq!(subbed, [0x8b, 0x84, 0xeb, 0x01]);
    }

    #[test]
    fn test_key_expansion() {
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let w = key_expansion(&key);
        assert_eq!(w[0], [0x2b, 0x7e, 0x15, 0x16]);
        assert_eq!(w[4], [0xa0, 0xfa, 0xfe, 0x17]);
        assert_eq!(w[43], [0xb6, 0x63, 0x0c, 0xa6]);
    }

    #[test]
    fn test_cypher() {
        let input = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let w = key_expansion(&key);
        let output = cypher(&input, &w);
        assert_eq!(output, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);
    }

    #[test]
    fn test_inv_cypher() {
        let input = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let w = key_expansion(&key);
        let output = cypher(&input, &w);
        let output2 = inv_cypher(&output, &w);
        assert_eq!(output2, input);
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let content = b"Hello World";
        // Get the path to the temp dir
        let plaintext_txt = std::env::temp_dir().join("plaintext.txt");
        let mut file = File::create(plaintext_txt.to_str().unwrap())?;
        file.write_all(content)?;

        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        // Save the key to a file
        let key_file = std::env::temp_dir().join("key.txt");
        let mut file = File::create(key_file.to_str().unwrap())?;
        file.write_all(&key)?;

        let ciphertext_txt = std::env::temp_dir().join("ciphertext.txt");
        encrypt_file(plaintext_txt.to_str().unwrap(), ciphertext_txt.to_str().unwrap() , key_file.to_str().unwrap())?;

        let unencrypted_txt = std::env::temp_dir().join("unencrypted.txt");
        decrypt_file(ciphertext_txt.to_str().unwrap(), unencrypted_txt.to_str().unwrap(), key_file.to_str().unwrap())?;

        let mut file = File::open(unencrypted_txt)?;
        let mut unencrypted_content = Vec::new();
        let _ = file.read_to_end(&mut unencrypted_content)?;

        assert_eq!(unencrypted_content, content);

        Ok(())
    }
}
