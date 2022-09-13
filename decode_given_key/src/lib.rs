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



pub struct Ngram {
    ngram_map: HashMap<String, f64>,
    len: usize,
    floor: f64,
}

impl Ngram {
    // calculates the log probabilities for some set of ngrams
    // code based off of python file from http://practicalcryptography.com/media/cryptanalysis/files/ngram_score_1.py
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
        }

        Ngram {
            ngram_map,
            len,
            floor: f64::log10(0.01/total_chars as f64)
        }
    }

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

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::Ngram;

    #[test]
    fn ngram_compute_score_works() {
        //tested against python code with same cipher text
        let f = File::open("../english_quadgrams.txt").unwrap();
        let ngram = Ngram::new(f);

        let mut ciphertext = String::from("Frank knew there was a correct time and place to reveal his secret and this wasn't it. The issue was that the secret might be revealed despite his best attempt to keep it from coming out. At this point, it was out of his control and completely dependant on those around him who also knew the secret. They wouldn't purposely reveal it, or at least he believed that, but they could easily inadvertently expose it. It was going to be a long hour as he nervously eyed everyone around the table hoping they would keep their mouths shut.
        He was an expert but not in a discipline that anyone could fully appreciate. He knew how to hold the cone just right so that the soft server ice-cream fell into it at the precise angle to form a perfect cone each and every time. It had taken years to perfect and he could now do it without even putting any thought behind it. Nobody seemed to fully understand the beauty of this accomplishment except for the new worker who watched in amazement.
        It really didn't matter what they did to him. He's already made up his mind. Whatever came his way, he was prepared for the consequences. He knew in his heart that the sacrifice he made was done with love and not hate no matter how others decided to spin it.");
        ciphertext.retain(|c| c.is_alphabetic()); // delete all non alphabetic characters
        ciphertext.make_ascii_uppercase();
        assert_eq!(-4052.0636388220714, ngram.compute_score(&ciphertext));


        let mut ciphertext = String::from("Rvtuy hlfa ggiei iel h qlpsips xvqq egk diydi gn vrzqee owp qfgedx nrp xapg tytr'g hx. Glq mlzib ubw ggeg xti llqocu qvflg fq vxcsxjfh qdwcmfi apg yctx nsxrqbx mv ybcq mg evbq osfpbd mvx. Ns xume thpbq, gu anr shx aj apg zmoxenp nrp ghtdicuiyx hrtqrwhbq mo xunwr edsnur egn aun eywa oglk qff wrbvrx. Flxf klsmha's thvbsllzv pfzrzp vx, av ta zbytx ud frpuiolr qfbx, otx glqc vviib fefhpl mzewcsorfrgkc rbbsll wq. Gu anr kbmzk mv pb y msaf lbyd el os kcszbtwyc qcxk sscscbmi nvaygk hec ueoki usbmgn hecz abtpq oqii avbgs qbtxuw elna.
        Vb ubw nm iktqvm iiq lpx vm e qmegbwzflf xuzx nrksgl qlsmh stpyc mtiyszgbxr. Gi xrqa avk qm isyc xui osgl xrqu vvflg wa xahh qff wbex fidzxy wzc-dvrzq sixp buhl gu eg slr tdivpgb yokyd xb javf h dbpgips gbrq itjv xle iidvl xuqx. Ph eye xnjia cqekz hl nfvsdgg ezh al qlsmh ana qs ux pphemvx ruia tgxmpbd yoc ggshktx ulvfle mg. Msospc llsjce xb eyypk ygksoqueac xui nitbhv mg xuhw ngosfwzfqiqrmx rboiia tlp ulr mij aavdlf tfp ansguip mg haxxfqrmx.
        Vx ditszv bjha's qnxfik dvxr ulrx hvh fs apa. Ec't eyqinhk qtks rn imf lmah. Iltasscs gnli ume atf, vb ubw cqicediw mco rii pnrficyxuqbq. Ii xmij mz lbz vbysx ggeg xti lhqoggmpd lr qmhx dop bprr vmgl xsol okb osg gegi zs fhhqcs lbv sglqvl kszgeiq ss ftur ba.");
        ciphertext.retain(|c| c.is_alphabetic());
        ciphertext.make_ascii_uppercase();
        assert_eq!(-8122.3612546735985 ,ngram.compute_score(&ciphertext));
    }
}