use keyphrase::KeyPhrase;
use std::io::{self, BufRead, stdin,stdout, Write};

const ASCII_UPPER_OFFSET: u8 = 65;
const ASCII_LOWER_OFFSET: u8 = 97; 
const KEYPHRASE_LEN: u8 = 26; 
fn main(){

    let mut plaintext = String::new();
    let stdin = io::stdin();

    let mut phrase  = String::new();

    stdin.lock().read_line(&mut plaintext).unwrap();
    
    plaintext.pop(); // pop off LF

    stdin.lock().read_line(&mut phrase).unwrap();
    phrase.pop(); // pop off LF
    let mut keyphrase = KeyPhrase::new(phrase).unwrap();

    let ciphertext = encode(&plaintext, &mut keyphrase);
    println!("{}",ciphertext);

}

pub fn encode(plaintext: &str, keyphrase: &mut KeyPhrase) -> String {
    let mut ciphertext = String::with_capacity(plaintext.len());


    for c in plaintext.chars() {
        if c.is_ascii_lowercase() {
            let offset = keyphrase.give_next_offset();
            let new_char = (((c as u8 - ASCII_LOWER_OFFSET + offset) % KEYPHRASE_LEN) + ASCII_LOWER_OFFSET) as char;
            //println!("{} + {}: {}", c, offset, new_char);
            ciphertext.push(new_char);
        }
        else if c.is_ascii_uppercase() {
            let offset = keyphrase.give_next_offset();
            let new_char = (((c as u8 - ASCII_UPPER_OFFSET + offset) % KEYPHRASE_LEN) + ASCII_UPPER_OFFSET) as char;
            //println!("{} + {}: {}", c, offset, new_char);
            ciphertext.push(new_char);
        }
        else {
            ciphertext.push(c);
        }
    }
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encode1() {
        let plaintext = "Hello world123!";
        let phrase = String::from("SECURITY");
        let mut keyphrase: KeyPhrase  = KeyPhrase::new(phrase).unwrap();
        assert_eq!("Zinff ehpdh123!", encode(plaintext, &mut keyphrase));
    }

    #[test]
    fn encode2() {
        let plaintext = "hell-o wor ld!";
        let phrase = String::from("SECURITY");
        let mut keyphrase: KeyPhrase  = KeyPhrase::new(phrase).unwrap();
        assert_eq!("zinf-f ehp dh!", encode(plaintext, &mut keyphrase));
    }
}