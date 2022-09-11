use std::{collections::HashMap, thread::current};
use keyphrase::{group_ciphertext, KeyPhrase, calculate_chi_squared};
use decode_given_key::decode;


fn main() {

}

pub fn decode_given_length(ciphertext: &str, key_length: usize, buckets: Vec<HashMap<char, usize>>) -> String{
    if key_length == 0 {
        return ciphertext.to_string();
    }
    let key = find_key(&buckets);

    println!("{}", key);
    let mut phrase = KeyPhrase::new(key).unwrap();
    return decode(ciphertext, &mut phrase);
}


pub fn find_key(buckets: &Vec<HashMap<char, usize>>) -> String {
    let mut key = String::with_capacity(30); // something default
    

    for (i, bucket) in buckets.iter().enumerate() { // buckets is our grouping based on key length
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



            eprintln!("{}", new_bucket);

            let mut new_bucket_map: HashMap<char, usize> = HashMap::new();
            for ch in new_bucket.chars() {
                if let Some(count) = new_bucket_map.get_mut(&ch) {
                    *count += 1;
                }
                else {
                    new_bucket_map.insert(ch, 1);
                }
            }

            let chi_sq = calculate_chi_squared(&new_bucket_map);
            if chi_sq < min {
                min = chi_sq;
                idx = i as i32;
            }
        }
        key.push( char::from_u32((65 + idx) as u32).unwrap());
    }

    key

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_length_14() {
        let mut ciphertext = String::from("Flx sckc mezo tbwf sy avb moi-fsvrif xhdb cjjgxdvrh, zsm xifrf hrzh oyf hxmwkguiyx sa mfw phm lsu. 
        Whhxpeei uf vbp tmqd, wui bebk bl ffiq ss glq pbnvq, rii fsvrif sk avb rpaa. Z gnv iel jcjgok qnaa xti lafbcu eac avxt lxy ook pygrxeifgalr xle xutqo mz xal ofp, tlr geq e bptu.");

        ciphertext.make_ascii_uppercase();
        
        let key_length = 14;
        let buckets = group_ciphertext(&ciphertext, key_length);
        
        let plaintext = decode_given_length(&ciphertext, key_length, buckets);
        assert_eq!(plaintext, "The lone lamp post of the one-street town flickered, not quite dead but definitely on its way out. Suitcase by her side, she paid no heed to the light, the street or the town. A car was coming down the street and with her arm outstretched and thumb in the air, she had a plan.")
    }
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