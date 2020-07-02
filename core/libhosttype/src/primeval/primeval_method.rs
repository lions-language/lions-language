use super::{PrimevalMethod};
use super::primeval_method_struct::*;

impl PrimevalMethod {
    pub fn from_function_meta() -> Self {
        PrimevalMethod::Uint32PlusUint32(Uint32PlusUint32::new(0, 1))
    }
}
