use serde::de;
use std::fmt;

const SIGNATURE_BYTES: usize = 64;

pub fn serialize<S: serde::Serializer>(
    value: &[u8; SIGNATURE_BYTES],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serde::Serialize::serialize(value.as_slice(), serializer)
}

pub fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; SIGNATURE_BYTES], D::Error> {
    deserializer.deserialize_tuple(SIGNATURE_BYTES, SignatureVisitor)
}

struct SignatureVisitor;
impl<'de> de::Visitor<'de> for SignatureVisitor {
    type Value = [u8; SIGNATURE_BYTES];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 64 signature bytes")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut signature = [0; SIGNATURE_BYTES];
        for (index, byte) in signature.iter_mut().enumerate() {
            *byte = sequence
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(index, &self))?;
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(SIGNATURE_BYTES + 1, &self));
        }
        Ok(signature)
    }
}
