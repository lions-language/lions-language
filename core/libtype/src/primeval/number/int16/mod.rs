use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Int16 {
    pub value: i16
}

impl Int16 {
    pub fn new(value: i16) -> Self {
        Self {
            value: value
        }
    }
}

