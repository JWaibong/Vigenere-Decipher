mod lib;
use lib::decode_given_length;
fn main() {

    decode_given_length("abcdefghijklmnopqrstuvwxyz", 3, None);
    
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test1 () {

    }

}