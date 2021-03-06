use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Int32 {
    pub value: i32
}

impl Int32 {
    pub fn new(value: i32) -> Self {
        Self {
            value: value
        }
    }
}

