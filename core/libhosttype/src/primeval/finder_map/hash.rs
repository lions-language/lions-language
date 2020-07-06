use crate::primeval::{FinderMap};
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::module::{ModuleKey};
use std::collections::{HashMap};

pub struct FunctionSet {
    mapping: HashMap<FunctionKey, FunctionAddress>
}

pub struct Finder {
    mod_map: HashMap<ModuleKey, FunctionSet>,
    map: HashMap<FunctionKey, FunctionAddress>
}

impl FinderMap for Finder {
    type FunctionSet = FunctionSet;

    fn module_exists(&self, module: &ModuleKey) -> Option<&FunctionSet> {
        self.mod_map.get(module)
    }

    fn find<'a>(&self, key: &FunctionKey, set: &'a FunctionSet) -> Option<&'a FunctionAddress> {
        /*
         * 这里的 set 就是查找, module 是否存在的时候传出去的
         * 如果第一步不传出来, 这里将再找一次module的value
         * */
        set.mapping.get(key)
    }
    
    fn find_module_method(&self, module: &ModuleKey, key: &FunctionKey)
        -> Option<&FunctionAddress> {
        match self.mod_map.get(module) {
            Some(ms) => {
                ms.mapping.get(key)
            },
            None => {
                None
            }
        }
    }

    fn find_method(&self, key: &FunctionKey) -> Option<&FunctionAddress> {
        self.map.get(key)
    }
}
