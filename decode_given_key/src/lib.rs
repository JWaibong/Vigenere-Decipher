use keyphrase::KeyPhrase;
use std::{collections::HashMap, fs::File,};
use std::io::{BufReader, BufRead};
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


    // calculates the log probabilities for some set of ngrams (in this case, the quadgrams in english_quadgrams.txt)
    // Ngram::new(), Ngram::compute_score() are based off of code in python file from
    // http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher-part-2/
    // http://practicalcryptography.com/media/cryptanalysis/files/ngram_score_1.py
    // CITED MULTIPLE TIMES BECAUSE THIS CODE IS THE MOST SIMILAR SNIPPETS I USED
pub struct Ngram {
    ngram_map: HashMap<String, f64>,
    len: usize,
    floor: f64,
}
impl Ngram {

    // http://practicalcryptography.com/media/cryptanalysis/files/ngram_score_1.py
    pub fn new(file: File) -> Ngram {
        let mut counts: HashMap<String,usize> = HashMap::new();
        let mut buf = String::with_capacity(100);
        let mut total_chars: usize = 0;
        let mut len = 0;

        let mut reader = BufReader::new(file);
        while let Ok(bytes) = reader.read_line(&mut buf) {
            if bytes == 0 {
                break;
            }
            buf.pop(); // pop LF
            let mut split = buf.split_ascii_whitespace();
            let key = split.next().unwrap().to_string();
            len = key.len();
            let count: usize = split.next().unwrap().parse().unwrap();
            total_chars += count;

            counts.insert(key, count);

            buf.clear();
        }

        let mut ngram_map: HashMap<String, f64> = HashMap::new();

        for (k,v) in counts {
            ngram_map.insert(k, f64::log10( v as f64 / total_chars as f64));
            // map an ngram to the log of its frequency
        }

        Ngram {
            ngram_map,
            len,
            floor: f64::log10(0.01/total_chars as f64)
        }
    }

    // http://practicalcryptography.com/media/cryptanalysis/files/ngram_score_1.py
    pub fn compute_score(&self, ciphertext: &str) -> f64 {
        let mut score = 0.0;

        for i in 0..ciphertext.len() - self.len + 1 {
            if let Some(prob) = self.ngram_map.get(&ciphertext[i..i+self.len]) {
                score += *prob;
            }
            else {
                score += self.floor;
            }
        }
        score
    }

    pub fn generate_key_from_parent(&self, mut parent: String, stripped_ciphertext: String) -> String {

        //let original_parent = parent.as_str().clone().as_bytes();
        let mut phrase = KeyPhrase::new(String::from(parent.as_str())).unwrap();

        let plaintext = decode(&stripped_ciphertext, &mut phrase);
        let parent_score = self.compute_score(&plaintext);
        let mut current_min_score = parent_score;

        let mut better_key_found = false;
        let mut better_letter_found = false; 

        let len = parent.len();

        loop {
            let best_key_found = String::from(parent.as_str());
            for i in 0..len {

                let mut current_min_char: u8 = 0;
                let original_char: u8 = *parent.as_bytes().get(i).unwrap();
                for j in 0..26 {
                    let c = 65 + j;

                    unsafe{
                        let bytes = parent.as_bytes_mut();
                        bytes[i] = c; // change the i'th character of parent key to variable c
                    }

                    let mut phrase = KeyPhrase::new(String::from(parent.as_str())).unwrap();

                    let plaintext = decode(&stripped_ciphertext, &mut phrase);

                    let score = self.compute_score(&plaintext);

                    if score > current_min_score {
                        better_key_found = true;
                        better_letter_found = true;
                        current_min_char = c;
                        current_min_score = score;
                    }
                }
                if better_letter_found {
                    unsafe{
                        let bytes = parent.as_bytes_mut();
                        bytes[i] = current_min_char; // if a better letter fits for the key, change the key to have that letter
                    }
                    better_letter_found = false;
                }
                else {
                    unsafe {
                        let bytes = parent.as_bytes_mut();
                        bytes[i] = original_char;
                    }
                }
            }
            if !better_key_found || parent.eq(&best_key_found) {
                return parent;
            }
        }
    }
}
