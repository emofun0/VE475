use bytes::Bytes;
use cipher::{KeyInit, KeySizeUser};
use cipher::{typenum, Key};
use rand;
use rand::rand_core::{CryptoRng};
use base64::{prelude::*};

const HILL_SIZE: usize = 8;
const KEY_SIZE: usize = HILL_SIZE * HILL_SIZE + 1; // 64+1=65

use crate::traits::{ChallengeCipher, DecryptBytes, EncryptBytes};

#[derive(Debug, Clone)]
struct HillCaesarError;
impl std::fmt::Display for HillCaesarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hill+Caesar cipher error")
    }
}
impl std::error::Error for HillCaesarError {}

#[derive(Clone)]
struct HillCaesarCipher;

impl KeySizeUser for HillCaesarCipher {
    type KeySize = typenum::U65;
    fn key_size() -> usize { KEY_SIZE }
}

impl KeyInit for HillCaesarCipher {
    fn new(_: &Key<Self>) -> Self { HillCaesarCipher{} }
}

fn modinv(a: i32, m: i32) -> Option<i32> {
    let (mut a, mut m) = (a, m);
    let (mut x0, mut x1) = (0, 1);
    if m == 1 { return Some(0); }
    while a > 1 {
        if m == 0 { return None; }
        let q = a / m;
        let mut t = m;
        m = a % m; a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if x1 < 0 { x1 += 256; }
    Some(x1)
}

fn det1(m: &[Vec<i32>]) -> i32 {
    let n = m.len();
    if n == 1 { return m[0][0]; }
    let mut res = 0;
    for (i, &v) in m[0].iter().enumerate() {
        let mut sub = vec![];
        for row in m.iter().skip(1) {
            let mut r = row.clone();
            r.remove(i);
            sub.push(r);
        }
        let sign = if i % 2 == 0 { 1 } else { -1 };
        res = (res + sign * v * det1(&sub)) % 256;
    }
    res
}

fn matrix_det(mat: &[[u8; HILL_SIZE]; HILL_SIZE]) -> i32 {
    let m: Vec<Vec<i32>> = mat.iter().map(|r| r.iter().map(|&x| x as i32).collect()).collect();
    let d = det1(&m);
    (d % 256 + 256) % 256
}

fn matrix_inv(mat: &[[u8; HILL_SIZE]; HILL_SIZE]) -> Option<[[u8; HILL_SIZE]; HILL_SIZE]> {
    let det = matrix_det(mat);
    if det == 0 { return None; }
    let inv_det = modinv(det, 256)?;
    let mut cof = [[0i32; HILL_SIZE]; HILL_SIZE];
    for i in 0..HILL_SIZE {
        #[allow(clippy::needless_range_loop)]
        for j in 0..HILL_SIZE {
            let mut sub = vec![];
            for (r, row) in mat.iter().enumerate() {
                if r == i { continue; }
                let mut rr = vec![];
                for (c, &v) in row.iter().enumerate() {
                    if c == j { continue; }
                    rr.push(v as i32);
                }
                sub.push(rr);
            }
            let sign = if (i + j) % 2 == 0 { 1 } else { -1 };
            let d = if sub.is_empty() { 1 } else { det1(&sub) };
            cof[j][i] = sign * d;
        }
    }
    let mut inv = [[0u8; HILL_SIZE]; HILL_SIZE];
    for i in 0..HILL_SIZE {
        for j in 0..HILL_SIZE {
            let v = ((cof[i][j] * inv_det) % 256 + 256) % 256;
            inv[i][j] = v as u8;
        }
    }
    Some(inv)
}

fn pad_bytes(mut v: Vec<u8>) -> Vec<u8> {
    let pad = HILL_SIZE - (v.len() % HILL_SIZE);
    if pad != HILL_SIZE {
        v.extend(vec![0u8; pad]);
    }
    v
}

fn unpad_bytes(mut v: Vec<u8>) -> Vec<u8> {
    while let Some(&0) = v.last() { v.pop(); }
    v
}

impl EncryptBytes for HillCaesarCipher {
    fn encrypt_bytes(key: &Key<Self>, message: Bytes) -> Bytes {
        let mat: [[u8; HILL_SIZE]; HILL_SIZE] = {
            let mut m = [[0u8; HILL_SIZE]; HILL_SIZE];
            for i in 0..HILL_SIZE {
                for j in 0..HILL_SIZE {
                    m[i][j] = key[i * HILL_SIZE + j];
                }
            }
            m
        };
        let caesar = key[KEY_SIZE-1];
        let input = pad_bytes(message.to_vec());
        let mut out = vec![];
        for chunk in input.chunks(HILL_SIZE) {
            let mut v = [0u8; HILL_SIZE];
            for (i, vi) in v.iter_mut().enumerate() {
                *vi = chunk.get(i).copied().unwrap_or(0);
            }
            let mut res = [0u8; HILL_SIZE];
            for i in 0..HILL_SIZE {
                let mut sum = 0u16;
                for (j, _) in v.iter().enumerate().take(HILL_SIZE) {
                    sum = sum.wrapping_add((mat[i][j] as u16) * (v[j] as u16));
                }
                res[i] = (sum % 256) as u8;
            }
            out.extend_from_slice(&res);
        }
        let encrypted: Vec<u8> = out.iter().map(|&b| b.wrapping_add(caesar)).collect();
        Bytes::from(encrypted)
    }
    fn gen_keys(mut rng: impl CryptoRng) -> Vec<u8> {
        loop {
            let mut mat = [0u8; HILL_SIZE*HILL_SIZE];
            rng.fill_bytes(&mut mat);
            let mut m = [[0u8; HILL_SIZE]; HILL_SIZE];
            for i in 0..HILL_SIZE {
                for j in 0..HILL_SIZE {
                    m[i][j] = mat[i*HILL_SIZE+j];
                }
            }
            if matrix_inv(&m).is_some() {
                let caesar = (rng.next_u32() % 256) as u8;
                let mut key = mat.to_vec();
                key.push(caesar);
                return key;
            }
        }
    }
}

impl DecryptBytes for HillCaesarCipher {
    type DecryptError = HillCaesarError;
    fn decrypt_bytes(key: &Key<Self>, message: Bytes) -> Result<Bytes, Self::DecryptError> {
        let mat: [[u8; HILL_SIZE]; HILL_SIZE] = {
            let mut m = [[0u8; HILL_SIZE]; HILL_SIZE];
            for i in 0..HILL_SIZE {
                for j in 0..HILL_SIZE {
                    m[i][j] = key[i * HILL_SIZE + j];
                }
            }
            m
        };
        let caesar = key[KEY_SIZE-1];
        let inv = matrix_inv(&mat).ok_or(HillCaesarError)?;
        let caesar_dec: Vec<u8> = message.iter().map(|&b| b.wrapping_sub(caesar)).collect();
        let mut out = vec![];
        for chunk in caesar_dec.chunks(HILL_SIZE) {
            let mut v = [0u8; HILL_SIZE];
            for (i, vi) in v.iter_mut().enumerate() {
                *vi = chunk.get(i).copied().unwrap_or(0);
            }
            let mut res = [0u8; HILL_SIZE];
            for i in 0..HILL_SIZE {
                let mut sum = 0i32;
                for (j, &vj) in v.iter().enumerate() {
                    sum = sum.wrapping_add((inv[i][j] as i32).wrapping_mul(vj as i32));
                }
                res[i] = ((sum % 256 + 256) % 256) as u8;
            }
            out.extend_from_slice(&res);
        }
        Ok(Bytes::from(unpad_bytes(out)))
    }
}

impl ChallengeCipher for HillCaesarCipher {
    fn secret() -> crate::traits::Secret<Self> {
        let key_b64 = "NzXLB/cPThBLYN3j/r9aV8/SIWuREranu1glYCilLBwm+WAcNDhIhZRn4sgkyk9kEaPUrcLGmSEn/STBziOvZvs=";
        let key_vec = base64::engine::general_purpose::STANDARD.decode(key_b64).unwrap();
        let key = *Key::<Self>::from_slice(&key_vec);
        let encrypted_message = "me+/QSSJ/R7d2Dbln17uWCHNjsWXJRt1peptplx4AxC8j7IMjkguBAxpw3E055PMJdfk3mHDGMRGlhflE0WV0KlWfwAARcRMadaxpqxMNyMd7ECpIkVsulQ1skRviVndw8i7p+EMsmZlhstXyXpP0NukEdsUVex7KWWAPMDpQpvJHyOShEdbpXFh/ySOYt5YBXwsL0uoHyRIUvTXUrsfVMMN+mj/BFwNSR4hiQQ3o37A4QCUb6kqcwkT4gGk+vz0fLYN5fcCkGdaLaKv76ZND3y0sB/uP6VoY3GyYQS/mLCER8A2mV2+CSG88IRlnTYlztpY23lCRNLegqFUdSPy+qhJ/q+vFxkcrijMLCtGwGS+4s/owk4FXzeDyugRCtRfjgOfxOsk1rNFbqYcEc5P3lRa1q4xUWJDZcBZmCy2Ih8VVfudYPPaGWLQ3WCben8gauF41ugaCLKlhQw6vwekbEiqg5UsbKjZ5Oa9XLGU97rCmWAd0W6CFTby9GHPqiH1Av4A9xQOujWqZQqx692ZJFckHNu9PSvqn2t3CDWIQli3bj5E5n8UnBGhLCLAPvxB6OMzTzwFFkNI00TpfNfxI+oJ8rAWuyYzWqEHZYH/cISpO/8Mj5gShoKdC+ZPt2nxRmaPN1nMkDXR1sMPMWPhjpUOwxr0QFU0uGxR6mrzOul//3IMuDD0BifYWxNt0ZQH7EFO11ahxviq1BYbfs+FO1bUp2ttSehUoylkCQSJCQ/xldwtSGQLbn59GPnPKnPDWoZb3q2iInzZMQF9Vn57CudmuZigJ2xRn8oT6dMGLQwW+1dXXy7fxB9YnFrgfcl+nVKJykxFy9v/KwThpPnNFfZm7bitsD9787iGfhmnLzu2SokqITR6zqSsp6H/emdLzlBUQaxxTBzx5FmkKOM9guAixxvtNBg9Z5r9QSzfOTi0wlnwB74+iMviQbPf4gFQ3sjditXRhxUblbAxcNkdDwwKhwpmSdQN5HWa4HfJ+Jvhe8kDeojCk03j5j/PlMAwZHjpX/l07liXJ0kRB523ygIoPXmKZ85mICxPrZOcDedJ+XXqPkFbtZsata+M7fJi2PMWSx+oqZcfgJDOlQalWKHWCk4cgmvWzhwVm+vrCBwX6Th8sndCwiQAU7tMPoYxZfZo3hgRZFclf3t3aLUwqu8bpeMPz51yjzi6/zO3lgqf1x1KnpGwa8BJDlZatUy3U4IDL1v5mk9XY+h5OKdcQD6YNadP2Qclvi3IBLTdkQHXWlK+nhaNHs58PtIEAtHU4ZhkaN8TQCEWigdTLnkqrPSYcG/HGNIoE9ivrvy4F4zgw1OtHZBdAON6I9M6NEjN8/euwwbfVTvIBJKgxykqz7hjU918yyNEMfP/+HD7n8kwfMJ1fmPiNEsxNoAV4nMnoW8EJHeTFcDpiJ9OZnW5MlrypK03KJRB7gdugO9Yb4CvBvyWbC3+WZTkZZstQHfTapMDc+MXex65/SlhL8K99V0wyv0RNj76MGo6qSUWnXGQw8xF8AWSy3S/JxjsWKep";
        crate::traits::Secret {
            key,
            encrypted_message: BASE64_STANDARD.decode(encrypted_message).map(Bytes::from).unwrap_or_default(),
        }
    }
}

pub fn main() {
    let cmd = crate::cli::command();
    HillCaesarCipher::execute(cmd, rand::rng());
}
