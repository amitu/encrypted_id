#[macro_use]
extern crate lazy_static;
use failure::Fail;
use std::sync::RwLock;
mod decrypt;
mod encrypt;
pub mod prelude;
#[cfg(test)]
mod test;

pub use self::{decrypt::decode_ekey, encrypt::encode_ekey};

pub type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Default)]
pub struct Config {
    secret_key: Option<String>,
    secret_key_bytes: Vec<u8>,
}

lazy_static! {
    pub(crate) static ref CONFIG: RwLock<Config> = RwLock::new(Config::default());
}

pub fn init_encrypt_conf(secret_key: &str) {
    let mut conf = CONFIG.write().unwrap();
    conf.secret_key = Some(secret_key.to_string());
    conf.secret_key_bytes = secret_key.as_bytes().to_owned();
}

pub trait Encrypt {
    fn ekey(id: u64) -> Result<String>;
}

pub trait Decrypt {
    fn dkey(ekey: &str) -> Result<u64>;
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "Encryption error: {:?}", _0)]
    Encrypt(crypto::symmetriccipher::SymmetricCipherError),

    #[fail(display = "Decryption error: {:?}", _0)]
    Decrypt(crypto::symmetriccipher::SymmetricCipherError),

    #[fail(display = "Invalid input")]
    InvalidInput,

    #[fail(display = "CRC mismatch")]
    CRCMismatch,

    #[fail(display = "SecretKey is none in encrypt config, initialize config first")]
    SecretKeyNotFound,
}
