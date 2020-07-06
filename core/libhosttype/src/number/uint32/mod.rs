use crate::primeval::{PrimevalMethod, PrimevalMethodMatched, PrimevalType};
use libcommon::function::{FunctionKey};

pub struct Uint32Data(u32);

pub enum Uint32Method {
    PlusOperatorUint32(Uint32Data)
}

impl PrimevalMethod {
    pub fn new_uint32_plus_operator_uint32(right_data: Uint32Data) -> Self {
        PrimevalMethod::Matched(PrimevalMethodMatched{
            typ: PrimevalType::Uint32(Uint32Method::PlusOperatorUint32(right_data)),
            func_key: FunctionKey::Static("uint32_+_uint32")
        })
    }
}

