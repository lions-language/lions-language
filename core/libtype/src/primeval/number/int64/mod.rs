use libmacro::NumberToStd;

#[derive(Debug, Clone, NumberToStd)]
pub struct Int64 {
    pub value: i64
}

impl Int64 {
    pub fn new(value: i64) -> Self {
        Self {
            value: value
        }
    }
}

