use crate::primeval::{FinderMap};
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::module::Module;
use std::collections::{HashMap};

pub struct FunctionSet {
    mapping: HashMap<FunctionKey, FunctionAddress>
}

pub struct Finder {
    mapping: HashMap<Module, FunctionSet>
}

impl FinderMap for Finder {
    type FunctionSet = FunctionSet;

    fn module_exists(&self, module: &Module) -> Option<&FunctionSet> {
        self.mapping.get(module)
    }

    fn find<'a>(&self, key: &FunctionKey, set: &'a FunctionSet) -> Option<&'a FunctionAddress> {
        /*
         * 这里的 set 就是查找, module 是否存在的时候传出去的
         * 如果第一步不传出来, 这里将再找一次module的value
         * */
        set.mapping.get(key)
    }
}
