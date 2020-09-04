use libtype::structure::{StructDefine};
use std::collections::HashMap;

struct DefineContainer {
    defines: HashMap<String, StructDefine>
}

impl DefineContainer {
    pub fn add_define(&mut self, name: String
        , define: StructDefine) {
        self.defines.insert(name, define);
    }

    pub fn find_define(&self, name: &str) -> Option<&StructDefine> {
        self.defines.get(name)
    }

    pub fn new() -> Self {
        Self {
            defines: HashMap::new()
        }
    }
}

/*
 * 模块 <-> 结构定义
 * */
pub struct StructControl {
    defines: HashMap<String, DefineContainer>
}

impl StructControl {
    pub fn add_define(&mut self, module_str: String
        , name: String, define: StructDefine) {
        match self.defines.get_mut(&module_str) {
            Some(c) => {
                /*
                 * 找到模块
                 * */
                c.add_define(name, define);
            },
            None => {
                /*
                 * 没有找到模块
                 *  1. 添加定义
                 *  2. 添加模块
                 * */
                let mut c = DefineContainer::new();
                c.add_define(name, define);
                self.defines.insert(module_str, c);
            }
        }
    }

    pub fn find_define(&self, module_str: &str
        , name: &str) -> Option<&StructDefine> {
        match self.defines.get(module_str) {
            Some(c) => {
                c.find_define(name)
            },
            None => {
                None
            }
        }
    }

    pub fn new() -> Self {
        Self {
            defines: HashMap::new()
        }
    }
}

