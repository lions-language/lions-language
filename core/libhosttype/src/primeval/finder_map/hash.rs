use crate::primeval::{FinderMap, PrimevalMethod};
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
    
    /*
     * 以下两个方法如果在一起使用, 将导致效率降低
     * 因为第一次 to_function_key 和第二次的是一样的
     * 所以不管先调用哪一个, 应该将计算过的 to_function_key 结果返回
     * */
    /*
    fn find_module_method(&self, module: &ModuleKey, method: &PrimevalMethod)
        -> Option<&FunctionAddress> {
        match self.mod_map.get(module) {
            Some(ms) => {
                ms.mapping.get(&method.to_function_key())
            },
            None => {
                None
            }
        }
    }

    fn find_method(&self, method: &PrimevalMethod) -> Option<&FunctionAddress> {
        self.map.get(&method.to_function_key())
    }
    */

    fn find_module_method(&self, module: &ModuleKey, method: &PrimevalMethod)
        -> (Option<&FunctionAddress>, Option<FunctionKey>) {
        match self.mod_map.get(module) {
            Some(ms) => {
                let key = method.to_function_key();
                match ms.mapping.get(&key) {
                    Some(v) => {
                        (Some(v), Some(key))
                    },
                    None => {
                        (None, None)
                    }
                }
            },
            None => {
                (None, None)
            }
        }
    }

    fn find_module_method_key(&self, module: &ModuleKey, key: &FunctionKey)
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

    fn find_method(&self, method: &PrimevalMethod)
        -> (Option<&FunctionAddress>, Option<FunctionKey>) {
        let key = method.to_function_key();
        match self.map.get(&key) {
            Some(v) => {
                (Some(v), Some(key))
            },
            None => {
                (None, None)
            }
        }
    }

    fn find_method_key(&self, key: &FunctionKey) -> Option<&FunctionAddress> {
        self.map.get(key)
    }
}
