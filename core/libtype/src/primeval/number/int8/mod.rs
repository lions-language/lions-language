use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Int8 {
    pub value: i8 
}

impl Int8 {
    pub fn new(value: i8) -> Self {
        Self {
            value: value
        }
    }
}

