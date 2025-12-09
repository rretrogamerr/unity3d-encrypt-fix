use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse().map_err(|e| format!("{e}"))?;

    let input = fs::read(&args.input).map_err(|e| format!("failed to read {:?}: {e}", args.input))?;

    let (fixed, padding_added, size_update) = normalize_unityfs_for_encryption(input);

    fs::write(&args.out_fixed, &fixed)
        .map_err(|e| format!("failed to write fixed file {:?}: {e}", args.out_fixed))?;

    let mut stdout = io::stdout();
    writeln!(stdout, "input:   {:?}", args.input).ok();
    writeln!(stdout, "fixed:   {:?}", args.out_fixed).ok();
    writeln!(stdout, "padding added: {padding_added} bytes").ok();
    if let Some((old_size, new_size)) = size_update {
        writeln!(stdout, "header size: {old_size} -> {new_size}").ok();
    } else {
        writeln!(stdout, "header size: not found (file did not look like UnityFS)").ok();
    }

    if args.fix_only {
        writeln!(stdout, "encryption: skipped (--fix-only)").ok();
        return Ok(());
    }

    let encrypted = encrypt_unity3d(&fixed).map_err(|e| format!("{e}"))?;

    fs::write(&args.out_encrypted, &encrypted)
        .map_err(|e| format!("failed to write encrypted file {:?}: {e}", args.out_encrypted))?;

    writeln!(stdout, "output:  {:?}", args.out_encrypted).ok();
    writeln!(stdout, "encryption: done").ok();

    Ok(())
}

#[derive(Debug)]
struct Args {
    input: PathBuf,
    out_fixed: PathBuf,
    out_encrypted: PathBuf,
    fix_only: bool,
}

impl Args {
    fn parse() -> Result<Self, &'static str> {
        let mut iter = env::args().skip(1);

        let input = match iter.next() {
            Some(p) => PathBuf::from(p),
            None => {
                eprintln!("usage: unity3d_fix <edited_decrypted.unity3d> [--out-fixed path] [--out-encrypted path] [--fix-only]");
                return Err("missing input file");
            }
        };

        let mut out_fixed: Option<PathBuf> = None;
        let mut out_encrypted: Option<PathBuf> = None;
        let mut fix_only = false;

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--out-fixed" | "-f" => {
                    out_fixed = iter.next().map(PathBuf::from);
                }
                "--out-encrypted" | "-e" => {
                    out_encrypted = iter.next().map(PathBuf::from);
                }
                "--fix-only" => {
                    fix_only = true;
                }
                _ => return Err("unknown argument"),
            }
        }

        let base = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output")
            .to_string();

        let default_fixed = input
            .with_file_name(format!("{base}_fixed.unity3d"));

        let default_encrypted = input
            .with_file_name(format!("{base}_ENCRYPTED.unity3d"));

        Ok(Args {
            input,
            out_fixed: out_fixed.unwrap_or(default_fixed),
            out_encrypted: out_encrypted.unwrap_or(default_encrypted),
            fix_only,
        })
    }
}

fn encrypt_unity3d(data: &[u8]) -> Result<Vec<u8>, String> {
    const KEY: [u8; 16] = [
        0x6D, 0x6B, 0x3A, 0x39, 0x74, 0x7A, 0x78, 0x57, 0x52, 0x46, 0x7D, 0x4A, 0x70, 0x7A, 0x77, 0x32,
    ];
    const IV: [u8; 16] = [
        0x4E, 0x46, 0x58, 0x6A, 0x65, 0x71, 0x28, 0x6E, 0x3A, 0x33, 0x67, 0x27, 0x38, 0x26, 0x3D, 0x3B,
    ];

    if data.len() % 16 != 0 {
        return Err("data length must be a multiple of 16 before encryption".to_string());
    }

    let round_keys = expand_key(KEY);
    let mut out = Vec::with_capacity(data.len());
    let mut prev = IV;

    for block in data.chunks(16) {
        let mut state = [0u8; 16];
        for i in 0..16 {
            state[i] = block[i] ^ prev[i];
        }

        aes_encrypt_block(&mut state, &round_keys);
        out.extend_from_slice(&state);
        prev = state;
    }

    Ok(out)
}

fn normalize_unityfs_for_encryption(data: Vec<u8>) -> (Vec<u8>, usize, Option<(u64, u64)>) {
    const BLOCK: usize = 16;

    // Try to parse UnityFS header for smarter padding placement (e.g., BlocksInfo at end).
    if let Some(header) = parse_unityfs_header(&data) {
        let mut out = Vec::with_capacity(data.len() + BLOCK);
        let total_len = data.len();
        let meta_at_end = header.flags & 0x80 != 0; // BlocksInfoAtTheEnd

        let (padding, new_len) = {
            let rem = total_len % BLOCK;
            if rem == 0 { (0, total_len) } else { (BLOCK - rem, total_len + (BLOCK - rem)) }
        };

        if padding == 0 {
            let tmp = data.clone();
            let updated = write_size_field(tmp, header.size_offset, total_len as u64)
                .unwrap_or_else(|d| d);
            return (updated, 0, Some((header.size, total_len as u64)));
        }

        if meta_at_end && header.csize as usize <= total_len {
            // Keep metadata as the physical tail; insert padding before it.
            let meta_len = header.csize as usize;
            if meta_len == 0 || meta_len > total_len {
                // Fallback to simple padding at end.
                let mut tmp = data.clone();
                tmp.extend(std::iter::repeat(0u8).take(padding));
                let new_len = tmp.len();
                let size_update = write_size_field(tmp, header.size_offset, new_len as u64)
                    .map(|d| {
                        let old = header.size;
                        let new = new_len as u64;
                        (d, Some((old, new)))
                    })
                    .unwrap_or_else(|d| (d, None));
                return (size_update.0, padding, size_update.1);
            }

            let data_part_len = total_len - meta_len;
            out.extend_from_slice(&data[..data_part_len]);
            out.extend(std::iter::repeat(0u8).take(padding));
            out.extend_from_slice(&data[data_part_len..]);

            let size_update = write_size_field(out, header.size_offset, new_len as u64)
                .map(|d| {
                    let old = header.size;
                    let new = new_len as u64;
                    (d, Some((old, new)))
                })
                .unwrap_or_else(|d| (d, None));
            return (size_update.0, padding, size_update.1);
        }

        // Default: pad at end.
        let mut tmp = data.clone();
        tmp.extend(std::iter::repeat(0u8).take(padding));
        let new_len = tmp.len();
        let size_update = write_size_field(tmp, header.size_offset, new_len as u64)
            .map(|d| {
                let old = header.size;
                let new = new_len as u64;
                (d, Some((old, new)))
            })
            .unwrap_or_else(|d| (d, None));
        return (size_update.0, padding, size_update.1);
    }

    // Fallback: simple padding at end, no header update.
    let mut data = data;
    let rem = data.len() % BLOCK;
    let padding = if rem == 0 { 0 } else { BLOCK - rem };
    if padding > 0 {
        data.extend(std::iter::repeat(0u8).take(padding));
    }
    (data, padding, None)
}

#[derive(Debug, Clone, Copy)]
struct UnityFsHeader {
    size_offset: usize,
    size: u64,
    csize: u32,
    flags: u32,
}

fn parse_unityfs_header(data: &[u8]) -> Option<UnityFsHeader> {
    const SIGNATURE: &[u8] = b"UnityFS\0"; // includes null terminator
    if data.len() < SIGNATURE.len() || &data[..SIGNATURE.len()] != SIGNATURE {
        return None;
    }

    let mut cursor = SIGNATURE.len();
    if cursor + 4 > data.len() {
        return None;
    }
    cursor += 4; // format (skip)

    cursor = skip_null_terminated(data, cursor)?; // unity version
    cursor = skip_null_terminated(data, cursor)?; // revision

    if cursor + 8 + 4 + 4 + 4 > data.len() {
        return None;
    }

    let size_offset = cursor;
    let size = read_be_u64(&data[size_offset..size_offset + 8]);
    let csize = u32::from_be_bytes(data[size_offset + 8..size_offset + 12].try_into().ok()?);
    let flags = u32::from_be_bytes(data[size_offset + 16..size_offset + 20].try_into().ok()?);

    Some(UnityFsHeader {
        size_offset,
        size,
        csize,
        flags,
    })
}

fn write_size_field(mut data: Vec<u8>, offset: usize, value: u64) -> Result<Vec<u8>, Vec<u8>> {
    if offset + 8 > data.len() {
        return Err(data);
    }
    write_be_u64(&mut data[offset..offset + 8], value);
    Ok(data)
}

fn skip_null_terminated(data: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i < data.len() {
        if data[i] == 0 {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn read_be_u64(bytes: &[u8]) -> u64 {
    ((bytes[0] as u64) << 56)
        | ((bytes[1] as u64) << 48)
        | ((bytes[2] as u64) << 40)
        | ((bytes[3] as u64) << 32)
        | ((bytes[4] as u64) << 24)
        | ((bytes[5] as u64) << 16)
        | ((bytes[6] as u64) << 8)
        | (bytes[7] as u64)
}

fn write_be_u64(bytes: &mut [u8], value: u64) {
    bytes[0] = (value >> 56) as u8;
    bytes[1] = (value >> 48) as u8;
    bytes[2] = (value >> 40) as u8;
    bytes[3] = (value >> 32) as u8;
    bytes[4] = (value >> 24) as u8;
    bytes[5] = (value >> 16) as u8;
    bytes[6] = (value >> 8) as u8;
    bytes[7] = value as u8;
}

// --- Minimal AES-128 implementation (encrypt only, no padding) ---

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
];

fn expand_key(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i][0] = key[4 * i];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }

    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / 4];
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }

    let mut round_keys = [[0u8; 16]; 11];
    for (r, chunk) in w.chunks(4).enumerate() {
        for i in 0..4 {
            round_keys[r][4 * i] = chunk[i][0];
            round_keys[r][4 * i + 1] = chunk[i][1];
            round_keys[r][4 * i + 2] = chunk[i][2];
            round_keys[r][4 * i + 3] = chunk[i][3];
        }
    }

    round_keys
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [SBOX[word[0] as usize], SBOX[word[1] as usize], SBOX[word[2] as usize], SBOX[word[3] as usize]]
}

fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

fn aes_encrypt_block(state: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    add_round_key(state, &round_keys[0]);

    for round in 1..10 {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &round_keys[round]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[10]);
}

fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    // row 1 left rotate by 1
    let tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;

    // row 2 left rotate by 2
    state.swap(2, 10);
    state.swap(6, 14);

    // row 3 left rotate by 3 (or right rotate by 1)
    let tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = tmp;
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let start = c * 4;
        let mut col = [state[start], state[start + 1], state[start + 2], state[start + 3]];
        mix_single_column(&mut col);
        state[start] = col[0];
        state[start + 1] = col[1];
        state[start + 2] = col[2];
        state[start + 3] = col[3];
    }
}

fn mix_single_column(col: &mut [u8; 4]) {
    let t = col[0] ^ col[1] ^ col[2] ^ col[3];
    let tmp = col[0];
    col[0] ^= t ^ xtime(col[0] ^ col[1]);
    col[1] ^= t ^ xtime(col[1] ^ col[2]);
    col[2] ^= t ^ xtime(col[2] ^ col[3]);
    col[3] ^= t ^ xtime(col[3] ^ tmp);
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (((x >> 7) & 1) * 0x1b)
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= round_key[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_vector() {
        // AES-128 ECB test vector (NIST SP 800-38A)
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let round_keys = expand_key(key);
        let mut block = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        aes_encrypt_block(&mut block, &round_keys);
        assert_eq!(block, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);
    }

    #[test]
    fn cbc_round_trip_padding() {
        let data = vec![1u8; 30];
        let (fixed, pad, _) = normalize_unityfs_for_encryption(data.clone());
        assert_eq!(pad, 2);
        assert_eq!(fixed.len() % 16, 0);

        let encrypted = encrypt_unity3d(&fixed).unwrap();
        assert_eq!(encrypted.len(), fixed.len());
    }

    #[test]
    fn blocks_info_at_end_padding_before_meta() {
        // Craft minimal UnityFS-like header with flags = 0xC3, csize = 4, size = len
        let mut data = Vec::new();
        data.extend_from_slice(b"UnityFS\0"); // signature
        data.extend_from_slice(&7u32.to_be_bytes()); // format
        data.extend_from_slice(b"5.x.x\0"); // unity ver
        data.extend_from_slice(b"2019.4.24f1\0"); // revision
        let size_offset = data.len();
        data.extend_from_slice(&0u64.to_be_bytes()); // size placeholder
        data.extend_from_slice(&4u32.to_be_bytes()); // csize
        data.extend_from_slice(&4u32.to_be_bytes()); // usize
        data.extend_from_slice(&0xC3u32.to_be_bytes()); // flags (blocks info at end)
        data.extend_from_slice(&[0u8; 12]); // padding to simulate header remainder
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // metadata (csize = 4)

        let total = data.len();
        // fill in size field
        let size_bytes = (total as u64).to_be_bytes();
        data[size_offset..size_offset + 8].copy_from_slice(&size_bytes);

        let (fixed, pad, size_update) = normalize_unityfs_for_encryption(data);
        assert_eq!(pad, (16 - (total % 16)) % 16);
        assert_eq!(fixed.len() % 16, 0);
        assert!(size_update.is_some());

        // metadata should still be last 4 bytes
        assert_eq!(&fixed[fixed.len() - 4..], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
