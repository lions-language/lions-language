use libmacro::{FieldGet, NumberToStd};

#[derive(Debug, Clone)]
pub enum BooleanValue {
    True,
    False
}

#[derive(Debug, Clone, FieldGet)]
pub struct Boolean {
    pub value: BooleanValue
}

impl Boolean {
    pub fn new(value: BooleanValue) -> Self {
        Self {
            value: value
        }
    }
}

