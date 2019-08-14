use failure::Fail;

mod decrypt;
mod encrypt;
#[cfg(test)]
mod test;

pub use self::{decrypt::decode_ekey, encrypt::encode_ekey};

pub type Result<T> = std::result::Result<T, failure::Error>;

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
}
