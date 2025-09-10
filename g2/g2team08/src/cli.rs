use crate::bytes::Bytes;

use base64::prelude::*;
use clap::{Parser, Subcommand};
use regex::Regex;
use std::{error::Error, fmt, path::PathBuf};

#[derive(Debug)]
pub struct IllegalCharacter(pub char);

impl fmt::Display for IllegalCharacter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal character \'{}\'", self.0)
    }
}

impl Error for IllegalCharacter {}

pub fn verified_message(message: &str) -> Result<&str, IllegalCharacter> {
    use once_cell::sync::Lazy;
    static ILLEGAL_CHARACTER: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[^[[:alnum:]]\,\.\;\?\!\(\)]").unwrap());

    match ILLEGAL_CHARACTER.find(message) {
        Some(m) => Err(IllegalCharacter(m.as_str().chars().next().unwrap())),
        None => Ok(message),
    }
}

pub fn parse_message(message: &str) -> Result<Bytes, IllegalCharacter> {
    verified_message(message).map(|message| message.bytes().collect())
}

pub fn parse_base64(value: &str) -> Result<Bytes, base64::DecodeError> {
    BASE64_STANDARD.decode(value).map(|bytes| bytes.into())
}

#[derive(Debug, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Generate a new key for the cipher
    Generate,
    /// Encrypt a secret message with the key in the given file, or with default key if not specified
    Encrypt {
        #[arg(
            help = "The secret message to encrypt",
            value_parser = parse_message
        )]
        secret_message: Bytes,
        #[arg(
            long, short, 
            help = "The key to use for encryption in base64 format. Priority over --key-file."
        )]
        key: Option<Bytes>,
        #[arg(
            long, 
            help = "Path to the file containing the key in base64 format. "
        )]
        key_file: Option<PathBuf>,
    },
    /// decrypt an encrypted message with the key in the given file, or with default key if not specified
    Decrypt {
        #[arg(value_parser = parse_base64)]
        encrypted_message: Bytes,
        #[arg(
            long, short, 
            help = "The key to use for encryption in base64 format. Priority over --key-file."
        )]
        key: Option<Bytes>,
        #[arg(
            long, 
            help = "Path to the file containing the key in base64 format. "
        )]
        key_file: Option<PathBuf>,
    },
}

#[derive(Debug, PartialEq, Eq, Parser)]
#[command(author, version, about, long_about)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

pub fn command() -> Command {
    Cli::parse().command
}
