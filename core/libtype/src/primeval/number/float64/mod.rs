#[derive(Debug, Clone)]
pub struct Float64 {
    pub value: f64
}

impl Float64 {
    pub fn new(value: f64) -> Self {
        Self {
            value: value
        }
    }
}

