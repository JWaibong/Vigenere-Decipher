use keyphrase::KeyPhrase;
const ASCII_UPPER_OFFSET: u8 = 65;
const ASCII_LOWER_OFFSET: u8 = 97; 
const KEYPHRASE_LEN: u8 = 26; 

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