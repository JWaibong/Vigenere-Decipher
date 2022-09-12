use std::{collections::HashMap, thread::current, fs::File};
use keyphrase::{group_ciphertext, KeyPhrase, calculate_chi_squared};
use decode_given_key::{decode, Ngram};


fn main() {

}

pub fn decode_given_length(ciphertext: &str, key_length: usize, buckets: Vec<HashMap<char, usize>>) -> String{
    if key_length == 0 {
        return ciphertext.to_string();
    }
    let new_key = find_key(&buckets);

    
    let f = File::open("/home/jwaibong/cse360/hw1/english_quadgrams.txt").unwrap();
    let ngram = Ngram::new(f);
    
    let mut stripped_ciphertext: String = String::from(ciphertext);
    stripped_ciphertext.retain(|c| c.is_alphabetic());
    stripped_ciphertext.make_ascii_uppercase();
    
    let new_key = ngram.generate_key_from_parent(new_key, stripped_ciphertext);
    


    println!("{}", new_key);
    let mut phrase = KeyPhrase::new(new_key).unwrap();
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

    //println!("{}", key);
    key

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_length_14() {
        let ciphertext = String::from("Flx swdfu anr shx ar mos cpprg osegt sy avb fpyfd. Xume atz gqpbrtd. Nhhk ghbzal'u vrlizfqv t awjc xlrm wui tew ljbp tirm mg sgx. Los emqtrc shx aj alf zys eac anpwiw ac qff hbnv. Vx iel zzfeixyx ewed egk gec lrrv xume qxhbq qpqrslvrs xxyffzmi. Fgi tizxef drqiiq slr hask vdbl brq geyp tik msxpt arqi eimpbgsa. Qvvcqmfi! Teiwm Ygsxucel! ihikfckc tlbtxrh.
        Ti mvch y tmc nj glq hkpbh. Ff anrr'g wgvx dvbriie gi ymwiw ph lp osg, ayg ef xapg jmnias mg huhg'a axruie.
        Rlr lmh fhrb gu ifoipmmpef tlp imz rs ui isnsr eywi snvpip mm kctl fzrm ms lq ltk oyqpphsiyc temlr fr.");

        let upper = ciphertext.to_ascii_uppercase();
        
        let key_length = 14;
        let buckets = group_ciphertext(&upper, key_length);
        
        let plaintext = decode_given_length(&ciphertext, key_length, buckets);
        assert_eq!(plaintext, "The light was out on the front porch of the house. This was strange. Judy couldn't remember a time when she had ever seen it out. She hopped out of her car and walked to the door. It was slightly ajar and she knew this meant something terrible. She gently pushed the door open and hall her fears were realized. Surprise! Happy Birthday! everyone shouted.
        He took a sip of the drink. He wasn't sure whether he liked it or not, but at this moment it didn't matter.
        She had made it especially for him so he would have forced it down even if he had absolutely hated it.")
    }

    #[test]
    fn decode_length_7() {
        let mut ciphertext = String::from("vptnvffuntshtarptymjwzirappljmhhqvsubwlzzygvtyitarptyiougxiuydtgzhhvvmum
        shwkzgstfmekvmpkswdgbilvjljmglmjfqwioiivknulvvfemioiemojtywdsajtwmtcgluy
        sdsumfbieugmvalvxkjduetukatymvkqzhvqvgvptytjwwldyeevquhlulwpkt");
        ciphertext.make_ascii_uppercase();

        let key_length = 7;
        let buckets = group_ciphertext(&ciphertext, key_length);
        
        let plaintext = decode_given_length(&ciphertext, key_length, buckets);
    }

    #[test]
    fn decode_length_7_2() {
        let ciphertext = String::from("Xmyl wpl'f eedovq nitbhfdgp. Mooq umw t sspqar mooq Bmr phg icmvgpbd. Fq eezc ocmpbgsa rtem swcc ielu'h byec. Mowp fmh vvab ye e loczi emgjs ec tew swscp e voookqh eptb. Fq ltasa rtem avfq iel avb rdymo okb ti lafrespxk hl zq ltwdv izsppbd rtem owp yewntdqgarl dsocz'x vvfocox. Al klsxhg'a fbyxmsl ikrup fbqe jmxxy wk jujx avxr flx kwcdugnsh lzextjzbq ti phg cyomgn heyf axys qywmgn otyk xal pbygxr pb ege pbms xr flbz alkqrm dcrjp yeawjyfief axiq lbz zfdq qnjv jmdi ulorrujns. Oij ti dust umw mooq yf xapg jmyiga kxq flta zfdq mlu'h xjierz pbygxbmii.
        Rtikl kxq m vxhgll rsk oso qtcglgp. Chikfckc mwlbabb ux ahr xjierz pbcz xalfb zgx los hlqa ulhqcd. Wal ykci xal suyox fvablf xahh qfq wafbbqe fxnok. Gf ltk pbcz xahh cyfiybz jmyiga oq rti ehyb. Rtikl ooc vyla glkq iolbqq flta rl rtem ac vmg.
        Xal vlsei phg imoemlr xr flx acm mr xal vfjx em avb czh hm o tgzhbuu ommh. Ba kxqz'x hijfmgw mos emgwx dop rtikl, prr qzxymllq mg actl wrxd heyf mm llfqfiw. Avbw iikl xrqf ees hlm mjkhwa ra iolf dm mrw zsb gf mg wsoqar.");
        
        let upper = ciphertext.to_ascii_uppercase();

        let key_length = 7;
        let buckets = group_ciphertext(&upper, key_length);
        
        let plaintext = decode_given_length(&ciphertext, key_length, buckets);

        assert_eq!("Life isn't always beautiful. That was a lesson that Dan was learning. He also realized that life wasn't easy. This had come as a shock since he had lived a charmed life. He hated that this was the truth and he struggled to be happy knowing that his assumptions weren't correct. He wouldn't realize until much later in life that the difficult obstacles he was facing that were taking away the beauty in his life at this moment would ultimately make his life much more beautiful. All he knew was that at this moment was that life isn't always beautiful.
        There was a reason for her shyness. Everyone assumed it had always been there but she knew better. She knew the exact moment that the shyness began. It had been that fateful moment at the lake. There are just some events that do that to you.
        The house was located at the top of the hill at the end of a winding road. It wasn't obvious the house was there, but everyone in town knew that it existed. They were just all too afraid to ever go and see it in person."
        , plaintext);
    }

}