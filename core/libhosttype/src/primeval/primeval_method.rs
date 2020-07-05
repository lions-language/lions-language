use super::{PrimevalMethod, PrimevalControl, FinderMap, PrimevalContext};
use crate::number::uint32::{Uint32Method};
use libcommon::function::{FunctionKey};
use libcompile::optcode::{OptCode};

impl PrimevalMethod {
    pub fn to_function_key(&self) -> FunctionKey {
        match self {
            PrimevalMethod::Uint32(e) => {
                match e {
                    Uint32Method::PlusOperatorUint32(_) => {
                        FunctionKey::Static("uint32_+_uint32")
                    }
                }
            },
            _ => {
                FunctionKey::Dynamic(String::new())
            }
        }
    }

    pub fn to_primeval_opt_code(&self) -> OptCode {
        match self {
            PrimevalMethod::Uint32(e) => {
                match e {
                    Uint32Method::PlusOperatorUint32(_) => {
                        OptCode::Uint32PlusOperatorUint32
                    }
                }
            },
            _ => {
                OptCode::Unknown
            }
        }
    }
}

/*
 * 下面的实现写在本文件中, 是为了不容易忘记更新
 * */
impl<M: FinderMap> PrimevalControl<M> {
    pub fn context(&self, method: &PrimevalMethod) -> &PrimevalContext<M> {
        match method {
            PrimevalMethod::Uint32(_) => {
                &self.uint32_method
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
}
