use crate::{decode_ekey, encode_ekey};
use std::fs::File;
use std::io::{BufRead, BufReader};

fn read_file(path: &str) -> Vec<String> {
    let f1: BufReader<File> =
        BufReader::new(File::open(path).expect(&format!("Not able to read file : {}", path)));
    let mut lines = vec![];
    for it in f1.lines() {
        lines.push(it.unwrap())
    }
    lines
}

fn read_secret_key() -> String {
    let secret_key = read_file("./secret_key.txt");
    secret_key
        .get(0)
        .map(|x| x.to_string())
        .expect("Could not found secret key")
}

fn read_tests() -> Vec<(u64, String)> {
    read_file("./test.txt")
        .into_iter()
        .map(|x| {
            let t = x.split(",").collect::<Vec<&str>>();
            (t[0].parse::<u64>().unwrap(), t[1].trim().to_string())
        })
        .collect::<Vec<(u64, String)>>()
}

#[test]
fn encrypted_id() {
    let secret_key: &str = &read_secret_key();
    let secret_key_bytes: &[u8] = secret_key.as_bytes();
    for (i, expected) in read_tests() {
        match decode_ekey(&expected, &format! {"{}", i}, secret_key, secret_key_bytes) {
            Ok(decoded) => assert_eq!(decoded, i),
            Err(err) => println!("{:?}", err),
        };

        match encode_ekey(i, &format! {"{}", i}, secret_key, secret_key_bytes) {
            Ok(encoded) => assert_eq!(encoded, expected),
            Err(_) => assert!(false),
        };
    }
}
