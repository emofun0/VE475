use crate::bytes::Bytes;
use crate::cipher::{Key, KeyInit};
use crate::cli::Command;
use rand::rand_core::{CryptoRng};

use base64::{prelude::*};
use std::{error::Error, fs};

#[derive(Debug, Clone)]
pub struct Secret<T: DecryptBytes> {
    pub key: Key<T>,
    pub encrypted_message: Bytes,
}

impl<T: DecryptBytes> Secret<T> {
    pub fn secret_message(&self) -> String {
        let message = T::decrypt_bytes(&self.key, self.encrypted_message.clone()).unwrap();
        String::from_utf8(message.into()).unwrap()
    }
}

pub trait EncryptBytes: KeyInit {
    fn encrypt_bytes(key: &Key<Self>, message: Bytes) -> Bytes;

    fn gen_keys(rng: impl CryptoRng) -> Vec<u8>;
}

pub trait DecryptBytes: KeyInit {
    type DecryptError: Error;
    fn decrypt_bytes(key: &Key<Self>, message: Bytes) -> Result<Bytes, Self::DecryptError>;
}

pub trait ChallengeCipher: EncryptBytes + DecryptBytes {
    fn secret() -> Secret<Self>;

    /// feel free to override this implementation
    /// this one has side-channel vulnerabilities
    fn execute(cmd: Command, rng: impl CryptoRng) {
        match cmd {
            Command::Generate => {
                println!("{}", BASE64_STANDARD.encode(Self::gen_keys(rng)))
            }
            Command::Encrypt {
                secret_message,
                key_file: path,
                key,
            } => {
                let key_content = match (key, path) {
                    (Some(key), _) => {
                        Some(BASE64_STANDARD.decode(key).unwrap())
                    }
                    (None, Some(path)) => {
                        let file_content = fs::read_to_string(&path).unwrap();
                        Some(BASE64_STANDARD.decode(file_content.trim()).unwrap())
                    }
                    (None, None) => None, 
                }   .map(|k| Key::<Self>::clone_from_slice(&k))
                    .unwrap_or(Self::secret().key);
                let encrypted_message = Self::encrypt_bytes(&key_content, secret_message.clone());
                println!("{}", BASE64_STANDARD.encode(encrypted_message));
            }
            Command::Decrypt {
                encrypted_message,
                key_file: path,
                key, 
            } => {
                if encrypted_message == Self::secret().encrypted_message && key.is_none() {
                    println!("cheater: it is forbidden to decrypt the challenge ciphertext");
                    return;
                } 
                let key_content = match (key, path) {
                    (Some(key), _) => {
                        Some(BASE64_STANDARD.decode(key).unwrap())
                    }
                    (None, Some(path)) => {
                        let file_content = fs::read_to_string(&path).unwrap();
                        Some(BASE64_STANDARD.decode(file_content.trim()).unwrap())
                    }
                    (None, None) => None, 
                }   .map(|k| Key::<Self>::clone_from_slice(&k))
                    .unwrap_or(Self::secret().key);
                let secret_message = Self::decrypt_bytes(&key_content, encrypted_message.clone()).unwrap();
                let secret_message = match String::from_utf8(secret_message.into()) {
                    Ok(s) => s,
                    Err(_) => {
                        println!("You should try harder :(");
                        return;
                    }
                };
                crate::cli::verified_message(&secret_message).unwrap();
                println!("{}", secret_message);
            }
        }
    }
}
