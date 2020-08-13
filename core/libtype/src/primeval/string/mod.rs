use libmacro::{FieldGet};

#[derive(Debug, Clone)]
pub enum StrValue {
    Utf8(String),
    VecU8(Vec<u8>)
}

#[derive(Debug, Clone, FieldGet)]
pub struct Str {
    pub value: StrValue
}

impl Str {
    pub fn extract_utf8(self) -> String {
        match self.value {
            StrValue::Utf8(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        }
    }

    pub fn extract_utf8_ref(&self) -> &String {
        match &self.value {
            StrValue::Utf8(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        }
    }

    pub fn extract_utf8_mut(&mut self) -> &mut String {
        match &mut self.value {
            StrValue::Utf8(v) => {
                v
            },
            _ => {
                panic!("should not happend: extract utf8, but found other");
            }
        }
    }

    pub fn extract_vecu8_ref(&self) -> &Vec<u8> {
        match &self.value {
            StrValue::VecU8(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        }
    }

    pub fn new(v: StrValue) -> Self {
        Self {
            value: v
        }
    }
}
