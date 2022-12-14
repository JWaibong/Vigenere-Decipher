
use std::collections::HashMap;


const ASCII_UPPER_OFFSET: u8 = 65;
//const ASCII_LOWER_OFFSET: u8 = 97; 

//http://cs.wellesley.edu/~fturbak/codman/letterfreq.html
const CHI_SQUARED_ENGLISH_EXPECTED_FREQ: [f64; 26]= [0.08167,0.01492,0.02782,0.04253,0.12702,0.02228,0.02015,0.06094,0.06966,0.00153,0.00772,
0.04025,0.02406,0.06749,0.07507,0.01929,0.00095,0.05987,0.06327,0.09056,0.02758,0.00978,
0.02360,0.00150,0.01974,0.00074];



pub struct KeyPhrase {
    phrase: String,
    current_idx: usize,
}

impl KeyPhrase {
    pub fn new(phrase: String) -> Option<KeyPhrase> {
        if phrase.len() == 0 {
            return None;
        }
        Some(KeyPhrase {
            phrase, 
            current_idx : 0
        })
    }
    pub fn give_next_offset(&mut self) -> u8 {

        let mut offset = *self.phrase.as_bytes().get(self.current_idx).unwrap() as u32;
        //println!("{}", offset);
        offset -= ASCII_UPPER_OFFSET as u32;

        if self.current_idx + 1 >= self.phrase.len() {
            self.current_idx = 0;
        }
        else {
            self.current_idx += 1;
        }
        offset as u8
    }

}

// group a ciphertext into key_length buckets
pub fn group_ciphertext(ciphertext: &str, key_length: usize) -> Vec<HashMap<char, usize>> {
    let mut buckets: Vec<HashMap<char, usize>> = Vec::with_capacity(key_length);
    for _ in 0..key_length {

        buckets.push(HashMap::new());
    }

    let mut i = 0;
    for c in ciphertext.chars() {
        if !c.is_ascii_alphabetic() {
            continue;
        }
        if i == key_length {
            i = 0;
        }

        
        let bucket = buckets.get_mut(i).unwrap();
        if let Some(value) = bucket.get_mut(&c) {
            *value += 1;
        }
        else {
            bucket.insert(c, 1);
        }

        i+=1;
    }
    buckets
}


// formula from 
// http://practicalcryptography.com/cryptanalysis/text-characterisation/index-coincidence/
pub fn calculate_ioc(bucket: &HashMap<char, usize>) -> f64 {
    let mut numerator: usize = 0;
    let mut denominator: usize = 0;

    for count in bucket.values() {
        numerator += count * (count - 1);
        denominator += *count;
    }

    if denominator == 1 {
        return numerator as f64;
    }
    if denominator == 0 || numerator == 0 {
        return 0.0;
    }
    let ret = numerator as f64 / ((denominator * (denominator - 1))as f64);
    if ret.is_nan() {
        return 0.0;
    }
    ret
}

// formula from 
// http://practicalcryptography.com/cryptanalysis/text-characterisation/chi-squared-statistic/
pub fn calculate_chi_squared(bucket: &HashMap<char, usize>, len: usize) -> f64 {
    let mut sum: f64 = 0.0;

    let mut c: u8 = 65;
    for i in 0..26 {
        if let Some(actual_count) = bucket.get(&(c as char)) {
            let expected_count: f64 = len as f64 * CHI_SQUARED_ENGLISH_EXPECTED_FREQ[i]; // denominator
            let numerator: f64 = (*actual_count as f64 - expected_count) * (*actual_count as f64 - expected_count);
            //eprintln!("{}: {}, expected = {}", c as char, *actual_count, expected_count);
            let frac = numerator / expected_count;
            sum += frac;
        }
        c += 1;
    }
    sum
}


#[cfg(test)]
mod tests {

    use crate::calculate_chi_squared;
    use super::*;
    #[test]
    fn chi_sq_works() {

        let seq = String::from("TSPXHSEPEESETEHOICMYESEIIOTUON");
        let mut bucket: HashMap<char, usize> = HashMap::new();
        for ch in seq.chars() {
            if let Some(val) = bucket.get_mut(&ch) {
                *val += 1;
            }
            else {
                bucket.insert(ch, 1);
            }
        }
        assert_eq!(30.42091198287971, calculate_chi_squared(&bucket, seq.len()));
    }

}