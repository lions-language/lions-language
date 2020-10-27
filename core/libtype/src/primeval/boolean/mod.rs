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
    pub fn to_std(&self) -> bool {
        match self.value {
            BooleanValue::True => {
                true
            },
            BooleanValue::False => {
                false
            }
        }
    }

    pub fn new(value: BooleanValue) -> Self {
        Self {
            value: value
        }
    }
}

