use primeval_method_struct::*;
use libcommon::module::Module;
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::typesof::function::{FunctionObject};

pub enum PrimevalMethod {
    Uint32PlusUint32(Uint32PlusUint32),
    None(FunctionObject)
}

pub trait FinderMap {
    /*
     * 关联类型
     * 这里使用关联类型是为了不进行二次查找
     * */
    type FunctionSet;

    fn module_exists(&self, module: &Module) -> Option<&Self::FunctionSet> {
        unimplemented!();
    }

    fn find<'a>(&self, key: &FunctionKey, set: &'a Self::FunctionSet) -> Option<&'a FunctionAddress> {
        unimplemented!();
    }
}

struct PrimevalContext<M>
    where M: FinderMap {
    primeval_set: PrimevalMethod,
    override_map: M,
    define_map: M
}

pub struct PrimevalControl<M>
    where M: FinderMap {
    context: PrimevalContext<M>
}

pub enum CompileResult {
    Address(FunctionAddress),
    SingleOptCode()
}

mod finder_map;
mod primeval_control;
mod primeval_method;
mod primeval_method_struct;

