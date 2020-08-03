use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Uint32 {
    pub value: u32
}

impl Uint32 {
    pub fn new(value: u32) -> Self {
        Self {
            value: value
        }
    }
}

