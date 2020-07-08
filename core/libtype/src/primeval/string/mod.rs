#[derive(Debug)]
pub enum StrValue {
    Utf8(String),
    VecU8(Vec<u8>)
}

#[derive(Debug)]
pub struct Str {
    pub value: StrValue
}

impl Str {
    pub fn new(v: StrValue) -> Self {
        Self {
            value: v
        }
    }
}
