use libmacro::NumberToStd;

#[derive(Debug, Clone)]
pub enum BooleanValue {
    True,
    False
}

#[derive(Debug, Clone)]
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

