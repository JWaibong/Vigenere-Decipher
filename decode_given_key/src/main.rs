use decode_given_key::decode;
use keyphrase::KeyPhrase;
use std::io::{BufRead, stdin};
// INDEX OF COINCIDENCE FOR MONOALPHABETIC CIPHER - 0.066 - 0.068
fn main(){
    // code snippet to read from stdin taken from
    // https://stackoverflow.com/questions/30186037/how-can-i-read-a-single-line-from-stdin
    let mut ciphertext = String::new();
    let stdin = stdin();
    let mut phrase  = String::new();
    stdin.lock().read_line(&mut ciphertext).unwrap();
    stdin.lock().read_line(&mut phrase).unwrap();

    ciphertext.pop(); // pop off LF
    phrase.pop(); // pop off LF

    let mut keyphrase = KeyPhrase::new(phrase).unwrap();
    let plaintext = decode(&ciphertext, &mut keyphrase);
    println!("{}",plaintext);
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