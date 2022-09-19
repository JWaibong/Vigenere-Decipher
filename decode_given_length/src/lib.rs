use std::{collections::HashMap, fs::File};
use keyphrase::{KeyPhrase, calculate_chi_squared};
use decode_given_key::{decode, Ngram};



pub fn decode_given_length(ciphertext: &str, key_length: usize, buckets: Vec<HashMap<char, usize>>) -> (String, String) {
    if key_length == 0 {
        return (String::new(), ciphertext.to_string());
    }
    let new_key = find_key(&buckets);

    
    let f = File::open("decode_given_length/src/english_quadgrams.txt").unwrap();
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


    #[test]
    fn ngram_compute_score_works() {
        //tested against python code with same cipher text
        let f = File::open("/home/jwaibong/cse360/hw1/decode_given_length/src/english_quadgrams.txt").unwrap();
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