use libcommon::optcode;
use libcommon::address::{FunctionAddress};
use libmacro::{FieldGet, FieldGetClone};
use crate::function::{CallFunctionParamAddr};
use crate::{AddressValue, AddressKey};
use crate::package::PackageStr;
use crate::primeval::string::Str;

#[derive(Debug, Clone)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
    pub param_addrs: Option<Vec<CallFunctionParamAddr>>,
    pub return_addr: AddressValue
}

#[derive(Debug, FieldGet, Clone)]
pub struct CallFunction {
    pub package_str: PackageStr,
    pub define_addr: FunctionAddress,
    pub return_addr: AddressValue
}

#[derive(Debug, Clone)]
pub struct VariantValue {
    pub direction: AddressValue
}

impl VariantValue {
    pub fn new(direction: AddressValue) -> Self {
        Self {
            direction: direction
        }
    }
}

#[derive(Debug, Clone)]
pub struct Uint8Static {
    pub addr: AddressKey,
    pub value: u8
}

#[derive(Debug, Clone)]
pub struct Uint16Static {
    pub addr: AddressKey,
    pub value: u16
}

#[derive(Debug, Clone)]
pub struct Uint32Static {
    pub addr: AddressKey,
    pub value: u32
}

#[derive(Debug, Clone)]
pub struct StringStatic {
    pub addr: AddressKey,
    pub value: Str
}

#[derive(Debug, Clone, FieldGet, FieldGetClone)]
pub struct StaticVariant {
    pub package_str: PackageStr,
    pub addr: AddressValue,
    pub static_addr: AddressKey
}

/*
 * 指令
 * */
#[derive(Debug, Clone)]
pub enum Instruction {
    LoadUint8Const(Uint8Static),
    LoadUint16Const(Uint16Static),
    LoadUint32Const(Uint32Static),
    LoadStringConst(StringStatic),
    LoadVariant(VariantValue),
    ReadStaticVariant(StaticVariant),
    CallPrimevalFunction(CallPrimevalFunction),
    CallFunction(CallFunction),
    Invalid
}
