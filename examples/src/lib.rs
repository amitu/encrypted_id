#[macro_use]
extern crate encry_derive;
extern crate encrypted_id;

use encrypted_id::prelude::*;

#[endecrypt(table_name = "table_name")]
#[derive(Debug, Default)]
pub struct EncyDemo {
    pub id: u64,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ency_test() {
        // Test 0
        let ekey = EncyDemo::ekey(10);
        // It should print Err(SecretKeyNotFound)
        println!("{:?}", ekey);

        // Test 1
        init_encrypt_conf("se(vh!38e21qca#9m7g0#5plq+a*z#imfjr10&iezsfmh6l)v(");
        assert_eq!(10, EncyDemo::dkey(&EncyDemo::ekey(10).unwrap()).unwrap());

        // Test 2
        let ekey = EncyDemo::ekey(10).unwrap();
        assert_eq!("46FFH6WeXx3aveZr3u2UOA".to_string(), ekey);
        // Passing wrong ekey to decode function
        let dkey = EncyDemo::dkey("46FFH6WeXx3bveZr3u2UOA");
        // It should print CRC Mismatch Error
        println!("{:?}", dkey);

        // Test 3
        // If reset in secret key
        init_encrypt_conf("se(vh!38e21qca#9m7g0#7tyq+a*z#imfjr10&iezsfmh6l)v(");
        let dkey = EncyDemo::dkey(&ekey);
        // It should print CRC Mismatch Error
        println!("{:?}", dkey);
    }
}
