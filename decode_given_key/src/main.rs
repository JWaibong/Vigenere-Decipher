use keyphrase::KeyPhrase;
use std::io::{self, BufRead, stdin,stdout, Write};

const ASCII_UPPER_OFFSET: u8 = 65;
const ASCII_LOWER_OFFSET: u8 = 97; 
const KEYPHRASE_LEN: u8 = 26; 
fn main(){

    let mut ciphertext = String::new();
    let stdin = stdin();
    let mut phrase  = String::new();

    stdin.lock().read_line(&mut ciphertext).unwrap();
    
    ciphertext.pop(); // pop off LF

    stdin.lock().read_line(&mut phrase).unwrap();
    phrase.pop(); // pop off LF

    let mut keyphrase = KeyPhrase::new(phrase).unwrap();

    let plaintext = decode(&ciphertext, &mut keyphrase);

    println!("{}",plaintext);

}
pub fn decode(ciphertext: &str, keyphrase: &mut KeyPhrase) -> String {
    let mut plaintext = String::with_capacity(ciphertext.len());
    for c in ciphertext.chars() {
        if c.is_ascii_lowercase() {
            let offset = keyphrase.give_next_offset();
            let c_numeric = c as u8 - ASCII_LOWER_OFFSET; 

            if offset > c_numeric {
                let new_char = (KEYPHRASE_LEN - offset + c_numeric + ASCII_LOWER_OFFSET) as char; // 26 - 20 + 6 = 12
                plaintext.push(new_char);
                
            }
            else {
                let new_char = (((c_numeric - offset) % KEYPHRASE_LEN) + ASCII_LOWER_OFFSET) as char;
                plaintext.push(new_char);
            }
        }
        else if c.is_ascii_uppercase() {
            let offset = keyphrase.give_next_offset();
            let c_numeric = c as u8 - ASCII_UPPER_OFFSET; 
            if offset > c_numeric {
                let new_char = (KEYPHRASE_LEN - offset + c_numeric + ASCII_UPPER_OFFSET) as char; 
                plaintext.push(new_char);
            }
            else {
                let new_char = (((c_numeric - offset) % KEYPHRASE_LEN) + ASCII_UPPER_OFFSET) as char;
                plaintext.push(new_char);
            } 
        }
        else {
            plaintext.push(c);
        }
    }
     plaintext
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode1() {
        let ciphertext = "Zinff ehpdh123!";
        let phrase = String::from("SECURITY");
        let mut keyphrase: KeyPhrase = KeyPhrase::new(phrase).unwrap();
        assert_eq!("Hello world123!", decode(ciphertext, &mut keyphrase));
    }

    #[test]
    fn decode2() {
        let ciphertext = "zinf-f ehp dh!";
        let phrase = String::from("SECURITY");
        let mut keyphrase: KeyPhrase  = KeyPhrase::new(phrase).unwrap();
        assert_eq!("hell-o wor ld!", decode(ciphertext, &mut keyphrase));
    }
}