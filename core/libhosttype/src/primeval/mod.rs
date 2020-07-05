use crate::number::uint32::{Uint32Method, Uint32Data};
use libcommon::module::{ModuleKey};
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::typesof::function::{FunctionObject};
use libcompile::optcode::OptCode;

pub enum PrimevalData {
    Uint32(Uint32Data)
}

pub enum PrimevalMethod {
    Uint32(Uint32Method),
    None(FunctionObject)
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

    /*
     * 查找含有 module 信息的方法
     * */
    fn find_module_method(&self, module: &ModuleKey, method: &PrimevalMethod)
        -> (Option<&FunctionAddress>, Option<FunctionKey>) {
        unimplemented!();
    }
    
    fn find_module_method_key(&self, module: &ModuleKey, key: &FunctionKey)
        -> Option<&FunctionAddress> {
        unimplemented!();
    }

    /*
     * 查找不含有 module 信息的方法
     * */
    fn find_method(&self, method: &PrimevalMethod)
        -> (Option<&FunctionAddress>, Option<FunctionKey>) {
        unimplemented!();
    }

    fn find_method_key(&self, key: &FunctionKey) -> Option<&FunctionAddress> {
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
    Undefine(Option<&'static str>)
}

pub enum FindMethodResult<'a> {
    Address(&'a FunctionAddress),
    SingleOptCode(OptCode),
    Panic(Panic)
}

mod finder_map;
mod primeval_control;
mod primeval_method;

