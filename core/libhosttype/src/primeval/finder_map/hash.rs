use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::module::{ModuleKey};
use std::collections::{HashMap};
use libtype::function::{Function};

pub struct FunctionSet {
    mapping: HashMap<String, Function>
}

impl FunctionSet {
    pub fn exists(&self, func_str: &str) -> Option<&Function> {
        self.mapping.get(func_str)
    }

    pub fn insert(&mut self, func_str: String
        , func: Function) {
        self.mapping.insert(func_str, func);
    }
}

/*
 * 如果是第一次定义的方法, 将写入到 map 中
 * 如果是重写的方法, 将写入到 mod_map 中
 * */
pub struct Finder {
    /*
     * 存储的是重写的方法
     * */
    mod_map: HashMap<String, FunctionSet>,
    /*
     * 存储的是第一次写入的方法
     * */
    map: HashMap<String, Function>
}

impl Finder {
    pub fn module_exists(&self, module_str: &str) -> Option<&FunctionSet> {
        self.mod_map.get(module_str)
    }

    pub fn module_exists_mut(&mut self, module_str: &str) -> Option<&mut FunctionSet> {
        self.mod_map.get_mut(module_str)
    }

    pub fn find<'a>(&self, func_str: &'a str, set: &'a FunctionSet) -> Option<&'a Function> {
        /*
         * 这里的 set 就是查找, module 是否存在的时候传出去的
         * 如果第一步不传出来, 这里将再找一次module的value
         * */
        set.mapping.get(func_str)
    }
    
    pub fn find_module_method(&self, module_str: &str, func_str: &str)
        -> Option<&Function> {
        match self.mod_map.get(module_str) {
            Some(ms) => {
                ms.mapping.get(func_str)
            },
            None => {
                None
            }
        }
    }

    pub fn find_method(&self, func_str: &str) -> Option<&Function> {
        self.map.get(func_str)
    }

    pub fn insert_module_method(&mut self, module_str: String, func_str: String
        , func: Function) {
        /*
         * 该方法是第一次插入, 在 module 不存在的情况下调用的
         * 所以需要新建 function_set
         * */
        let mut mapping = HashMap::new();
        mapping.insert(func_str, func);
        self.mod_map.insert(module_str, FunctionSet{
            mapping: mapping
        });
    }

    pub fn insert_method(&mut self, func_str: String, func: Function) {
        self.map.insert(func_str, func);
    }
}

impl Finder {
    pub fn new() -> Self {
        Self {
            mod_map: HashMap::new(),
            map: HashMap::new()
        }
    }
}
