use std::{collections::HashMap, fs::File};
use keyphrase::{KeyPhrase, calculate_chi_squared};
use decode_given_key::{decode, Ngram};



pub fn decode_given_length(ciphertext: &str, key_length: usize, buckets: Vec<HashMap<char, usize>>) -> (String, String) {
    if key_length == 0 {
        return (String::new(), ciphertext.to_string());
    }
    let new_key = find_key(&buckets);

    
    let f = File::open("../english_quadgrams.txt").unwrap();
    // citing here again for what an ngram is and what source code I used.
    //  http://practicalcryptography.com/media/cryptanalysis/files/ngram_score_1.py
    //  http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-vigenere-cipher-part-2/
    let ngram = Ngram::new(f);
    
    let mut stripped_ciphertext: String = String::from(ciphertext);
    stripped_ciphertext.retain(|c| c.is_alphabetic());
    stripped_ciphertext.make_ascii_uppercase();

    let new_key = ngram.generate_key_from_parent(new_key, stripped_ciphertext);
    
    let copy_key = String::from(new_key.as_str());
    let mut phrase = KeyPhrase::new(new_key).unwrap();
    return (copy_key, decode(ciphertext, &mut phrase));
}


// http://practicalcryptography.com/cryptanalysis/text-characterisation/chi-squared-statistic/
pub fn find_key(buckets: &Vec<HashMap<char, usize>>) -> String {
    let mut key = String::with_capacity(100); // something default
    

    for (_, bucket) in buckets.iter().enumerate() { // buckets is our grouping based on key length
        let mut min: f64 = f64::MAX;
        let mut idx: i32 = -1;
        for j in 0..26 { // for each bucket, we need to test 26 caesar ciphers and pick the most likely one based on chi-squared test

            let mut new_bucket = String::with_capacity(100);
            for (ch, count) in bucket {
                for _ in 0..*count {
                    new_bucket.push(*ch);
                }
            }

            let current_shift = char::from_u32(65 + j).unwrap();
            let mut phrase = String::with_capacity(1);
            phrase.push(current_shift);

            let mut phrase = KeyPhrase::new(phrase).unwrap();
            let new_bucket = decode(&new_bucket, &mut phrase);

            //eprintln!("{}", new_bucket);
            let mut new_bucket_map: HashMap<char, usize> = HashMap::new();
            for ch in new_bucket.chars() {
                if let Some(count) = new_bucket_map.get_mut(&ch) {
                    *count += 1;
                }
                else {
                    new_bucket_map.insert(ch, 1);
                }
            }

            let chi_sq = calculate_chi_squared(&new_bucket_map, new_bucket.len());
            if chi_sq < min {
                min = chi_sq;
                idx = j as i32;
            }
        }
        key.push( char::from_u32((65 + idx) as u32).unwrap());
    }
    key

}