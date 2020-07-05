use super::{PrimevalType};

impl PrimevalType {
    pub fn to_str(&self) -> &'static str {
        match self {
            PrimevalType::Uint32(_) => {
                "uint32"
            }
        }
    }
}