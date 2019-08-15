use base64;
use byteorder::{LittleEndian, WriteBytesExt};
use crc;
use crypto::{
    self, aes, blockmodes,
    buffer::{self, BufferResult, ReadBuffer, WriteBuffer},
    digest::Digest,
    sha2,
};

use crate::{Error, Result, CONFIG};

pub fn encode_ekey(
    id: u64,
    sub_key: &str,
    secret_key: &str,
    secret_key_bytes: &[u8],
) -> Result<String> {
    let version: u32 = 1;
    let crc: u32 = crc::crc32::checksum_ieee(id.to_string().as_bytes()) & 0xffffffff;

    let mut msg: Vec<u8> = vec![];
    msg.write_u32::<LittleEndian>(crc)?;
    msg.write_u64::<LittleEndian>(id)?;
    msg.write_u32::<LittleEndian>(version)?;

    let mut sha_value = sha2::Sha256::new();
    sha_value.input_str(&format!("{}{}", secret_key, sub_key));
    let mut iv: Vec<u8> = vec![0; 32];
    sha_value.result(&mut iv);
    let iv = &iv[..16];
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        &secret_key_bytes[..32],
        iv,
        blockmodes::NoPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(msg.as_ref());
    let mut buffer = [0; 16];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true);

        let result = match result {
            Ok(v) => v,
            Err(e) => return Err(Error::Encrypt(e).into()),
        };

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(base64::encode_config(&final_result, base64::URL_SAFE).replace("=", ""))
}

pub fn encode_ekey_util(id: u64, sub_key: &str) -> Result<String> {
    let config = CONFIG.read().unwrap();
    if config.secret_key.is_none() {
        return Err(Error::SecretKeyNotFound.into());
    }
    encode_ekey(
        id,
        sub_key,
        config.secret_key.as_ref().unwrap(),
        config.secret_key_bytes.as_ref(),
    )
}
