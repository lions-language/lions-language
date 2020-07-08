#[derive(Debug)]
pub struct Uint64 {
    pub value: u64
}

impl Uint64 {
    pub fn new(value: u64) -> Self {
        Self {
            value: value
        }
    }
}

