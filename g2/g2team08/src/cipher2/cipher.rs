use bytes::Bytes;
use cipher::{KeyInit, KeySizeUser};
use cipher::{typenum, Key};
use rand;
use rand::rand_core::CryptoRng;
use base64::{prelude::*};

use crate::traits::{ChallengeCipher, DecryptBytes, EncryptBytes};

const CHACHA20_KEY_SIZE: usize = 32;
const CHACHA20_NONCE_SIZE: usize = 12;
const CHACHA20_COUNTER_SIZE: usize = 4;
const CHACHA20_TOTAL_KEY_SIZE: usize = CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE + CHACHA20_COUNTER_SIZE;

#[derive(Debug, Clone)]
struct ChaCha20Error;
impl std::fmt::Display for ChaCha20Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChaCha20 cipher error")
    }
}
impl std::error::Error for ChaCha20Error {}

#[derive(Clone)]
struct ChaCha20Cipher;

impl KeySizeUser for ChaCha20Cipher {
    type KeySize = typenum::U48;
    fn key_size() -> usize { CHACHA20_TOTAL_KEY_SIZE }
}

impl KeyInit for ChaCha20Cipher {
    fn new(_: &Key<Self>) -> Self { ChaCha20Cipher{} }
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);
    
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);
    
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);
    
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

fn chacha20_block(key: &[u8; CHACHA20_KEY_SIZE], nonce: &[u8; CHACHA20_NONCE_SIZE], counter: u32) -> [u8; 64] {
    let mut state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];
    
    // little-endian
    for i in 0..8 {
        state[i + 4] = u32::from_le_bytes([
            key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]
        ]);
    }
    
    for i in 0..3 {
        state[i + 13] = u32::from_le_bytes([
            nonce[i * 4], nonce[i * 4 + 1], nonce[i * 4 + 2], nonce[i * 4 + 3]
        ]);
    }
    
    state[12] = counter;
    
    let mut working_state = state;
    
    for _ in 0..10 {
        {
            let (a, b, c, d) = (working_state[0], working_state[4], working_state[8], working_state[12]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[0] = a;
            working_state[4] = b;
            working_state[8] = c;
            working_state[12] = d;
        }
        {
            let (a, b, c, d) = (working_state[1], working_state[5], working_state[9], working_state[13]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[1] = a;
            working_state[5] = b;
            working_state[9] = c;
            working_state[13] = d;
        }
        {
            let (a, b, c, d) = (working_state[2], working_state[6], working_state[10], working_state[14]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[2] = a;
            working_state[6] = b;
            working_state[10] = c;
            working_state[14] = d;
        }
        {
            let (a, b, c, d) = (working_state[3], working_state[7], working_state[11], working_state[15]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[3] = a;
            working_state[7] = b;
            working_state[11] = c;
            working_state[15] = d;
        }
        
        {
            let (a, b, c, d) = (working_state[0], working_state[5], working_state[10], working_state[15]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[0] = a;
            working_state[5] = b;
            working_state[10] = c;
            working_state[15] = d;
        }
        {
            let (a, b, c, d) = (working_state[1], working_state[6], working_state[11], working_state[12]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[1] = a;
            working_state[6] = b;
            working_state[11] = c;
            working_state[12] = d;
        }
        {
            let (a, b, c, d) = (working_state[2], working_state[7], working_state[8], working_state[13]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[2] = a;
            working_state[7] = b;
            working_state[8] = c;
            working_state[13] = d;
        }
        {
            let (a, b, c, d) = (working_state[3], working_state[4], working_state[9], working_state[14]);
            let (mut a, mut b, mut c, mut d) = (a, b, c, d);
            quarter_round(&mut a, &mut b, &mut c, &mut d);
            working_state[3] = a;
            working_state[4] = b;
            working_state[9] = c;
            working_state[14] = d;
        }
    }
    
    for i in 0..16 {
        working_state[i] = working_state[i].wrapping_add(state[i]);
    }
    
    let mut output = [0u8; 64];
    for i in 0..16 {
        let bytes = working_state[i].to_le_bytes();
        output[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    
    output
}

impl EncryptBytes for ChaCha20Cipher {
    fn encrypt_bytes(key: &Key<Self>, message: Bytes) -> Bytes {
        let key_bytes = &key[..CHACHA20_KEY_SIZE];
        let nonce_bytes = &key[CHACHA20_KEY_SIZE..CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE];
        let counter_bytes = &key[CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE..];
        
        let key_array: [u8; CHACHA20_KEY_SIZE] = key_bytes.try_into().unwrap();
        let nonce_array: [u8; CHACHA20_NONCE_SIZE] = nonce_bytes.try_into().unwrap();
        let counter = u32::from_le_bytes(counter_bytes.try_into().unwrap());
        
        let mut output = Vec::new();
        let message_bytes = message.to_vec();
        
        for (block_index, chunk) in message_bytes.chunks(64).enumerate() {
            let keystream = chacha20_block(&key_array, &nonce_array, counter + block_index as u32);
            
            for (i, &byte) in chunk.iter().enumerate() {
                output.push(byte ^ keystream[i]);
            }
        }
        
        Bytes::from(output)
    }
    
    fn gen_keys(mut rng: impl CryptoRng) -> Vec<u8> {
        let mut key = vec![0u8; CHACHA20_TOTAL_KEY_SIZE];
        rng.fill_bytes(&mut key);
        key
    }
}

impl DecryptBytes for ChaCha20Cipher {
    type DecryptError = ChaCha20Error;
    
    fn decrypt_bytes(key: &Key<Self>, message: Bytes) -> Result<Bytes, Self::DecryptError> {
        Ok(Self::encrypt_bytes(key, message))
    }
}

impl ChallengeCipher for ChaCha20Cipher {
    fn secret() -> crate::traits::Secret<Self> {
        let mut key_vec = vec![0u8; CHACHA20_TOTAL_KEY_SIZE];
        for (i, v) in key_vec.iter_mut().take(CHACHA20_KEY_SIZE).enumerate() {
            *v = i as u8;
        }
        for (i, v) in key_vec.iter_mut().skip(CHACHA20_KEY_SIZE).take(CHACHA20_NONCE_SIZE).enumerate() {
            *v = (i + 100) as u8;
        }
        for (i, v) in key_vec.iter_mut().skip(CHACHA20_KEY_SIZE + CHACHA20_NONCE_SIZE).take(CHACHA20_COUNTER_SIZE).enumerate() {
            *v = (i + 200) as u8;
        }
        
        let key = *Key::<Self>::from_slice(&key_vec);
        let encrypted_message = "YHc8b6k/vHFPIUacaUmkKtAwCEumnb8A3isiaoKjzajzZQiBNIecpvDAskZ5QrpC6w4+9R0grybvSiVTjHKM89ifdyAS3yACxTj9uXWV2E+Ml3BK4wqROa/DCBH6nUfjX0WXpSz0xMQGLCR38KWRQi0AupL/no+K71Diuto52xAIBJA/1zxW9vx8pinSI6tqAMoI6qyjlco9TT+6kmmVrf0iOIfX6wA9bCFxD+xu3znowCZ2xMJiitgKaqFVYIO497dzWsSMGpWymG2/Y8omgmpSMmQHEp0q2px9222zUNtCNjswoEUgy+1m7mGKrFiLbIlf/8r7ysONgPezfKo4eHii5xRmKnSlP5lxUz6i7SEfG8M49oIJLN3nUl1p8Q6g54orm+G/dnNzVloQKxoNWMe4p+o2pbT4aAum1mxWDjO5/bgsXmsG4MQAr1EeYWy9wtaLXnEu2m1vxaD2INAzxDanQviEjhxxOFs2YAn2z4T6k38ekQ+tTynSZ4FHWD55h34ZqwcTtCqDlqFrZtmoExHEUbyEM3gIsF/IQE87ZO66I+rWW15Y6tqEfSFz/mLRtdz5CUkhZZKCtHfAvhCZ7G/TW8tOvJfZOwjmxp/sFf0J9ZsWDowEjxC7ewOFByGTcuZ9Bl75F11gkC6SlMfETlsSd/xm5o1pBmiQFgd4DK1Htoifpd149suj1R44ajqUzzpJMlVU/LcSMTUJnjQiL8YXTpD00036DU/sszd1BoNB6Z1/LElrJL3LD+6jTdnTt/8LYFR/G0OFJAbBemMlWOpdIvquFL2AWDLp1W0WbS03r5eEiZTaZj9CChOny11Geml/Dk2Zdd63CazLnm1hTUpjv4yRSCYv4z5E8A+dlcFNQ+jcdlgkvi7OHZOV0RukbgJAO9cQC004aTmRGmVZrvhVIf6fDeLnNSVr/cKOdG6O7+Cs8mtq2Vwn8jWtJu3cRstCWpaRCNzAWKlA/SJZnMJt0Vzt3y4bKw==";
        crate::traits::Secret {
            key,
            encrypted_message: BASE64_STANDARD.decode(encrypted_message).map(Bytes::from).unwrap_or_default(),
        }
    }
}

pub fn main() {
    let cmd = crate::cli::command();
    ChaCha20Cipher::execute(cmd, rand::rng());
}
