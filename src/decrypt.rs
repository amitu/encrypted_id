use crate::{Error, Result, CONFIG};
use base64;
use byteorder::{LittleEndian, ReadBytesExt};
use crc;
use crypto::{
    self, aes, blockmodes,
    buffer::{self, BufferResult, ReadBuffer, WriteBuffer},
    digest::Digest,
    sha2,
};
use std::io::Cursor;

pub fn decode_ekey(
    ekey: &str,
    sub_key: &str,
    secret_key: &str,
    secret_key_bytes: &[u8],
) -> Result<u64> {
    if ekey.len() == 0 {
        return Err(Error::InvalidInput.into());
    }
    let ekey = ekey.to_string();
    let padding: String = vec!['='; 3 - ekey.len() % 3].into_iter().collect();
    let ekey = ekey + &padding.to_string();
    let emsg = match base64::decode_config(&ekey, base64::URL_SAFE) {
        Ok(m) => m,
        Err(_) => return Err(Error::InvalidInput.into()),
    };

    let mut sha = sha2::Sha256::new();
    sha.input_str(&format!("{}{}", secret_key, sub_key));
    let mut iv: Vec<u8> = vec![0; 32];
    sha.result(&mut iv);
    let iv = &iv[..16];

    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        &secret_key_bytes[..32],
        iv,
        blockmodes::NoPadding,
    );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(&emsg);
    let mut buffer = [0; 16];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true);
        let result = match result {
            Ok(v) => v,
            Err(e) => return Err(Error::Decrypt(e).into()),
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

    let mut rdr = Cursor::new(final_result);
    let crc = rdr.read_u32::<LittleEndian>()? & 0xffffffff;
    let id = rdr.read_u64::<LittleEndian>()?;
    let version = rdr.read_u32::<LittleEndian>()?;

    let expected_crc: u32;
    if version == 0 {
        expected_crc = crc::crc32::checksum_ieee(&vec![0; id as usize]) & 0xffffffff;
    } else {
        let id_bytes: String = id.to_string();
        let id_bytes = id_bytes.as_bytes();
        expected_crc = crc::crc32::checksum_ieee(id_bytes) & 0xffffffff;
    }

    if crc != expected_crc {
        return Err(Error::CRCMismatch.into());
    }

    Ok(id)
}

pub fn decode_ekey_util(ekey: &str, sub_key: &str) -> Result<u64> {
    let config = CONFIG.read().unwrap();
    if config.secret_key.is_none() {
        return Err(Error::SecretKeyNotFound.into());
    }
    decode_ekey(
        ekey,
        sub_key,
        config.secret_key.as_ref().unwrap(),
        config.secret_key_bytes.as_ref(),
    )
}
