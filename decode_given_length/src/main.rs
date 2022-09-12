mod lib;
use std::io::{stdin, BufRead};

use keyphrase::{group_ciphertext};
use lib::decode_given_length;
fn main() {

    let mut ciphertext = String::new();
    let stdin = stdin();
    let mut len  = String::new();

    stdin.lock().read_line(&mut ciphertext).unwrap();
    
    ciphertext.pop(); // pop off LF

    stdin.lock().read_line(&mut len).unwrap();
    len.pop(); // pop off LF

    let len: usize = len.parse().unwrap();
    let buckets = group_ciphertext(&ciphertext, len);

    let plaintext = decode_given_length(&ciphertext, len, buckets);

    println!("{}",plaintext);
}