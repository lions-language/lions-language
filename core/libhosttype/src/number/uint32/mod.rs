use crate::primeval::{PrimevalData};
use libcommon::typesof::function::{FunctionObject};

pub enum Uint32Method {
    PlusOperatorUint32(PrimevalData)
}

pub struct Uint32Data(u32);
