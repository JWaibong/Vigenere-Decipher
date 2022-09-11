use std::{collections::HashMap};
use keyphrase::{group_ciphertext, find_key, KeyPhrase};
use decode_given_key::decode;

pub fn decode_given_length(ciphertext: &str, key_length: usize, buckets: Option<Vec<HashMap<char, usize>>>) -> String {
    if key_length == 0 {
        return ciphertext.to_string();
    }

    let mut plaintext = String::with_capacity(ciphertext.len());

    if let Some(buckets) = buckets {
       let key: String = find_key(&buckets);
       let mut phrase = KeyPhrase::new(key).unwrap();
       return decode(ciphertext, &mut phrase);

    }
    else {
        let buckets = group_ciphertext(ciphertext, key_length);
        let key = find_key(&buckets);

        let mut phrase = KeyPhrase::new(key).unwrap();
        return decode(ciphertext, &mut phrase);
    }

    

    plaintext

}

    /*let sorted_buckets: Vec<Vec<(char,usize)>> = buckets.iter().map(|bucket| {
        let mut sorted: Vec<(char, usize)> = bucket.iter().map(|(k,v)| (*k,*v)).collect();
        sorted.sort();
        sorted
    }).collect();*/
    /*for bucket in sorted_buckets {
        
        for (k,v) in bucket.iter() {
            println!("{} : {}", k, v);
        }
        println!("New bucket");
    }*/