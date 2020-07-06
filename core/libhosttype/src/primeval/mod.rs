use crate::number::uint32::{Uint32Method, Uint32Data};
use libcommon::module::{ModuleKey};
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::typesof::function::{FunctionObject};
use libcompile::optcode::OptCode;

pub enum PrimevalData {
    Uint32(Uint32Data)
}

pub enum PrimevalType {
    Uint32(Uint32Method)
}

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
    primeval_set: PrimevalMethod,
    define_map: M
}

pub struct PrimevalControl<M>
    where M: FinderMap {
    uint32_method: PrimevalContext<M>
}

pub enum Panic {
    Undefine(Option<&'static str>),
    AlreadyDefine
}

pub enum FindMethodResult<'a> {
    Address(&'a FunctionAddress),
    SingleOptCode(OptCode),
    Panic(Panic)
}

pub enum AddMethodResult {
    Panic(Panic),
    Success
}

mod finder_map;
mod primeval_control;
mod primeval_method;
mod primeval_type;

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

