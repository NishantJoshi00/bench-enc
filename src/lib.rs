use rand::{distributions::Alphanumeric, Rng};
use ring::aead::{self, BoundKey, OpeningKey, SealingKey, UnboundKey};

type R<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Debug)]
struct NonceSequence(u128);

impl NonceSequence {
    /// Byte index at which sequence number starts in a 16-byte (128-bit) sequence.
    /// This byte index considers the big endian order used while encoding and decoding the nonce
    /// to/from a 128-bit unsigned integer.
    const SEQUENCE_NUMBER_START_INDEX: usize = 4;

    /// Generate a random nonce sequence.
    fn new() -> Result<Self, ring::error::Unspecified> {
        use ring::rand::{SecureRandom, SystemRandom};

        let rng = SystemRandom::new();

        // 96-bit sequence number, stored in a 128-bit unsigned integer in big-endian order
        let mut sequence_number = [0_u8; 128 / 8];
        rng.fill(&mut sequence_number[Self::SEQUENCE_NUMBER_START_INDEX..])?;
        let sequence_number = u128::from_be_bytes(sequence_number);

        Ok(Self(sequence_number))
    }

    /// Returns the current nonce value as bytes.
    fn current(&self) -> [u8; ring::aead::NONCE_LEN] {
        let mut nonce = [0_u8; ring::aead::NONCE_LEN];
        nonce.copy_from_slice(&self.0.to_be_bytes()[Self::SEQUENCE_NUMBER_START_INDEX..]);
        nonce
    }

    /// Constructs a nonce sequence from bytes
    fn from_bytes(bytes: [u8; ring::aead::NONCE_LEN]) -> Self {
        let mut sequence_number = [0_u8; 128 / 8];
        sequence_number[Self::SEQUENCE_NUMBER_START_INDEX..].copy_from_slice(&bytes);
        let sequence_number = u128::from_be_bytes(sequence_number);
        Self(sequence_number)
    }
}

impl ring::aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let mut nonce = [0_u8; ring::aead::NONCE_LEN];
        nonce.copy_from_slice(&self.0.to_be_bytes()[Self::SEQUENCE_NUMBER_START_INDEX..]);

        // Increment sequence number
        self.0 = self.0.wrapping_add(1);

        // Return previous sequence number as bytes
        Ok(ring::aead::Nonce::assume_unique_for_key(nonce))
    }
}

/// Trait for cryptographically encoding a message
pub trait EncodeMessage {
    /// Takes in a secret and the message and encodes it, returning bytes
    fn encode_message(
        &self,
        _secret: &[u8],
        _msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/// Trait for cryptographically decoding a message
pub trait DecodeMessage {
    /// Takes in a secret, an encoded messages and attempts to decode it, returning bytes
    fn decode_message(
        &self,
        _secret: &[u8],
        _msg: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

#[derive(Debug)]
pub struct GcmAes256;

impl EncodeMessage for GcmAes256 {
    fn encode_message(
        &self,
        secret: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let nonce_sequence = NonceSequence::new().unwrap();
        let current_nonce = nonce_sequence.current();
        let key = UnboundKey::new(&aead::AES_256_GCM, secret).unwrap();
        let mut key = SealingKey::new(key, nonce_sequence);
        let mut in_out = msg.to_vec();

        key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
            .unwrap();
        in_out.splice(0..0, current_nonce);

        Ok(in_out)
    }
}

impl DecodeMessage for GcmAes256 {
    fn decode_message(
        &self,
        secret: &[u8],
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = UnboundKey::new(&aead::AES_256_GCM, secret).unwrap();

        let nonce_sequence =
            NonceSequence::from_bytes(msg[..ring::aead::NONCE_LEN].try_into().unwrap());

        let mut key = OpeningKey::new(key, nonce_sequence);
        let mut binding = msg;
        let output = binding.as_mut_slice();

        let result = key
            .open_within(aead::Aad::empty(), output, ring::aead::NONCE_LEN..)
            .unwrap();

        Ok(result.into())
    }
}

#[inline]
pub fn generate_aes256_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use ring::rand::SecureRandom;

    let rng = ring::rand::SystemRandom::new();
    let mut key: [u8; 256 / 8] = [0_u8; 256 / 8];
    rng.fill(&mut key).unwrap();
    Ok(key)
}

pub fn string_generation(size: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .map(char::from)
        .collect::<String>()
}

pub fn encrypt_with_key(data: String, key: [u8; 32]) -> R<Vec<u8>> {
    EncodeMessage::encode_message(&GcmAes256, &key, data.as_bytes())
}

pub fn encrypt_and_generate_key(data: String) -> R<(Vec<u8>, [u8; 32])> {
    let key = generate_aes256_key()?;
    encrypt_with_key(data, key).map(|data| (data, key))
}

pub fn decrypt_with_key(data: Vec<u8>, key: [u8; 32]) -> R<String> {
    DecodeMessage::decode_message(&GcmAes256, &key, data)
        .and_then(|data| Ok(std::str::from_utf8(&data).map(String::from)?))
}



#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_and_decrypt() {
        let data = string_generation(1000);
        let (enc_data, key) = encrypt_and_generate_key(data.clone()).unwrap();
        let r_data = decrypt_with_key(enc_data, key).unwrap();
        assert_eq!(data, r_data)
    }
}

