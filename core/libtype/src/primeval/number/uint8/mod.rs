use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Uint8 {
    pub value: u8
}

impl Uint8 {
    pub fn new(value: u8) -> Self {
        Self {
            value: value
        }
    }
}

