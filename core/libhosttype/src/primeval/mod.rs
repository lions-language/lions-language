use libcommon::function::FunctionKey;
use libcommon::typesof::function::{FunctionObject};
use libcommon::optcode::OptCode;
use libtype::{Type};
use libtype::primeval::{PrimevalType};
use libtype::function::{Function};

pub struct PrimevalMethod {
    pub typ: PrimevalType,
    pub func_key: FunctionKey
}

pub struct PrimevalContext {
    define_map: finder_map::hash::Finder
}

impl PrimevalContext {
    fn new() -> Self {
        Self {
            define_map: finder_map::hash::Finder::new()
        }
    }
}

pub struct PrimevalControl {
    int8_method: PrimevalContext,
    int16_method: PrimevalContext,
    int32_method: PrimevalContext,
    int64_method: PrimevalContext,
    uint8_method: PrimevalContext,
    uint16_method: PrimevalContext,
    uint32_method: PrimevalContext,
    uint64_method: PrimevalContext,
    float32_method: PrimevalContext,
    float64_method: PrimevalContext,
    string_method: PrimevalContext
}

impl PrimevalControl {
    pub fn new() -> Self {
        Self {
            int8_method: PrimevalContext::new(),
            int16_method: PrimevalContext::new(),
            int32_method: PrimevalContext::new(),
            int64_method: PrimevalContext::new(),
            uint8_method: PrimevalContext::new(),
            uint16_method: PrimevalContext::new(),
            uint32_method: PrimevalContext::new(),
            uint64_method: PrimevalContext::new(),
            float32_method: PrimevalContext::new(),
            float64_method: PrimevalContext::new(),
            string_method: PrimevalContext::new(),
        }
    }
}

pub mod finder_map;
mod primeval_control;

impl PrimevalMethod {
    pub fn new(typ: PrimevalType, func_obj: FunctionObject) -> Self {
        let mut key_s = String::from(typ.to_str());
        key_s.push('_');
        key_s.push_str(func_obj.function_string());
        Self {
            typ: typ,
            func_key: FunctionKey::new(key_s)
        }
    }

    pub fn from_func_key(typ: PrimevalType, func_key: FunctionKey) -> Self {
        Self {
            typ: typ,
            func_key: func_key
        }
    }
}

pub struct PrimevalMethodBindValue {
    single_optcode: OptCode
}

use crate::number::uint32;
use crate::number::uint8;
pub fn primeval_method(typ: &Type, func_str: &str) -> Option<&'static Function> {
    match typ {
        Type::Primeval(p) => {
            match &p.typ {
                PrimevalType::Uint8 => {
                    uint8::get_method(func_str)
                },
                PrimevalType::Uint32 => {
                    uint32::get_method(func_str)
                },
                _ => {
                    unimplemented!();
                }
            }
        },
        _ => {
            unimplemented!();
        }
    }
}

