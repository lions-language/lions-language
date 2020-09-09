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

    pub fn length(&self) -> usize {
        self.defines.len()
    }
    
    pub fn print_defines(&self) {
        for define in self.defines.iter() {
            println!("{:?}", define);
        }
    }

    pub fn print_members_struct_fields(&self) {
        for (_, define) in self.defines.iter() {
            match define.member_ref() {
                Some(m) => {
                    m.print_members_struct_fields();
                },
                None => {}
            }
        }
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

    pub fn define_length(&self, module_str: &str) -> usize {
        match self.defines.get(module_str) {
            Some(c) => {
                c.length()
            },
            None => {
                0
            }
        }
    }

    pub fn print_defines(&self) {
        for (_, define) in self.defines.iter() {
            define.print_defines();
        }
    }

    pub fn print_members_struct_fields(&self) {
        for (_, define) in self.defines.iter() {
            define.print_members_struct_fields();
        }
    }

    pub fn new() -> Self {
        Self {
            defines: HashMap::new()
        }
    }
}

