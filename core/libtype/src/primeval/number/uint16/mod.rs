use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Uint16 {
    pub value: u16
}

impl Uint16 {
    pub fn new(value: u16) -> Self {
        Self {
            value: value
        }
    }
}

