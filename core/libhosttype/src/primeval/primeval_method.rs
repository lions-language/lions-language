use super::{PrimevalMethod};

impl PrimevalMethod {
    pub fn to_string(&self) -> String {
        match self {
            PrimevalMethod::Uint32PlusUint32(_) => {
                String::from("uint32_+_uint32")
            },
            _ => {
                String::new()
            }
        }
    }
}
