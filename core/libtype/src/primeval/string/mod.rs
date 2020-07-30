#[derive(Debug, Clone)]
pub enum StrValue {
    Utf8(String),
    VecU8(Vec<u8>)
}

#[derive(Debug, Clone)]
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
