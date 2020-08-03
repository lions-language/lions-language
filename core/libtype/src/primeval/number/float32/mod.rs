#[derive(Debug, Clone)]
pub struct Float32 {
    pub value: f32
}

impl Float32 {
    pub fn new(value: f32) -> Self {
        Self {
            value: value
        }
    }
}

