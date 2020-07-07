use crate::number::int8::{Int8};
use crate::number::int16::{Int16};
use crate::number::int32::{Int32};
use crate::number::int64::{Int64};
use crate::number::uint8::{Uint8};
use crate::number::uint16::{Uint16};
use crate::number::uint32::{Uint32};
use crate::number::uint64::{Uint64};
use crate::number::float32::{Float32};
use crate::number::float64::{Float64};
use crate::string::{Str};
use libcommon::module::{ModuleKey};
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::typesof::function::{FunctionObject};
use libcommon::optcode::OptCode;
use phf::{phf_map};

#[derive(Debug)]
pub enum PrimevalType {
    Uint8(Option<Uint8>),
    Uint16(Option<Uint16>),
    Uint32(Option<Uint32>),
    Uint64(Option<Uint64>),
    Int8(Option<Int8>),
    Int16(Option<Int16>),
    Int32(Option<Int32>),
    Int64(Option<Int64>),
    Float32(Option<Float32>),
    Float64(Option<Float64>),
    Str(Option<Str>)
}

/*
pub struct PrimevalMethodMatched {
    pub typ: PrimevalType,
    /*
     * 因为原生类型提供的方法的签名是固定的, 为了降低运行时消耗, 将 func_key 定义为静态的
    * */
    pub func_key: FunctionKey
}

pub struct PrimevalMethodRightNotMatched {
    pub typ: PrimevalType,
    pub func_key: FunctionKey
}

pub enum PrimevalMethod {
    /*
     * 与原生类型的方法匹配, 可能就是原生类型方法, 也可能是原生类型方法的重写
     * */
    Matched(PrimevalMethodMatched),
    /*
     * 是原生类型的拓展方法 (属于原生类型, 但是方法不是原生类型提供的)
     * */
    RightNotMatched(PrimevalMethodRightNotMatched)
}
*/
pub struct PrimevalMethod {
    pub typ: PrimevalType,
    pub func_key: FunctionKey
}

pub trait FinderMap {
    /*
     * 关联类型
     * 这里使用关联类型是为了不进行二次查找
     * */
    type FunctionSet;

    fn module_exists(&self, module: &ModuleKey) -> Option<&Self::FunctionSet> {
        unimplemented!();
    }

    fn find<'a>(&self, key: &FunctionKey, set: &'a Self::FunctionSet) -> Option<&'a FunctionAddress> {
        unimplemented!();
    }

    fn find_module_method(&self, module: &ModuleKey, key: &FunctionKey)
        -> Option<&FunctionAddress> {
        unimplemented!();
    }

    fn find_method(&self, key: &FunctionKey) -> Option<&FunctionAddress> {
        unimplemented!();
    }

    fn insert_module_method(&mut self, module: &ModuleKey, key: &FunctionKey
        , addr: FunctionAddress) {
        unimplemented!();
    }

    fn insert_method(&mut self, key: &FunctionKey, addr: FunctionAddress) {
        unimplemented!();
    }
}

pub struct PrimevalContext<M>
    where M: FinderMap {
    define_map: M
}

pub struct PrimevalControl<M>
    where M: FinderMap {
    int8_method: PrimevalContext<M>,
    int16_method: PrimevalContext<M>,
    int32_method: PrimevalContext<M>,
    int64_method: PrimevalContext<M>,
    uint8_method: PrimevalContext<M>,
    uint16_method: PrimevalContext<M>,
    uint32_method: PrimevalContext<M>,
    uint64_method: PrimevalContext<M>,
    float32_method: PrimevalContext<M>,
    float64_method: PrimevalContext<M>,
    string_method: PrimevalContext<M>
}

pub enum Panic {
    Undefine(Option<&'static str>),
    AlreadyDefine
}

pub enum FindMethodResult<'a> {
    Address(&'a FunctionAddress),
    SingleOptCode(&'static OptCode),
    Panic(Panic)
}

pub enum AddMethodResult {
    Panic(Panic),
    Success
}

pub mod finder_map;
mod primeval_control;
mod primeval_method;
mod primeval_type;

/*
impl PrimevalMethod {
    pub fn new_primeval_type_right_not_matched(typ: PrimevalType, func_obj: FunctionObject)
        /* 
         * 为原生类型扩展方法
         * 在 new 的时候进行 function key 的构造, 之后在使用的时候就不需要构建了
         * */
        -> Self {
        let mut key_s = String::from(typ.to_str());
        key_s.push('_');
        key_s.push_str(func_obj.function_string());
        PrimevalMethod::RightNotMatched(PrimevalMethodRightNotMatched{
            typ: typ,
            func_key: FunctionKey::Dynamic(key_s)
        })
    }
}
*/

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

/*
 * 完美hash
 * 静态映射
 * */
static PRIMEVAL_METHOD_MAP: phf::Map<&'static str, PrimevalMethodBindValue> = phf_map! {
    "uint32_+_uint32" => PrimevalMethodBindValue{
        single_optcode: OptCode::Uint32PlusOperatorUint32
    }
};

pub fn primeval_method(key: &FunctionKey) -> Option<&'static PrimevalMethodBindValue> {
    PRIMEVAL_METHOD_MAP.get(key.key_ref())
}

