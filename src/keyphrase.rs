
const ASCII_UPPER_OFFSET: u8 = 65;
const ASCII_LOWER_OFFSET: u8 = 97; 
pub struct KeyPhrase {
    phrase: String,
    currentIdx: usize,
}

impl KeyPhrase {
    pub fn new(phrase: String) -> Option<KeyPhrase> {
        if phrase.len() == 0 {
            return None;
        }
        Some(KeyPhrase {
            phrase, 
            currentIdx : 0
        })
    }
    pub fn give_next_offset(&mut self) -> u8 {

        let offset = *self.phrase.as_bytes().get(self.currentIdx).unwrap() - ASCII_UPPER_OFFSET;

        if self.currentIdx + 1 >= self.phrase.len() {
            self.currentIdx = 0;
        }
        else {
            self.currentIdx += 1;
        }
        offset
    }

}