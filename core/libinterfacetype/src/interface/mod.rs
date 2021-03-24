use libtype::interface::{InterfaceDefine};
use std::collections::HashMap;
use libcommon::ptr::{HeapPtr, Heap};

/*
 * NOTE NOTE NOTE
 * 这里不能将 InterfaceDefine 存储到 value 中
 * 因为HashMap扩容的原因, 将导致写入 Type 中的地址变为无效的
 * 所以, 当是 Interface 的时候, Type 中存储 HeapPtr 而不是 RefPtr
 * */
struct DefineContainer {
    defines: HashMap<String, HeapPtr>
}

impl DefineContainer {
    pub fn add_define(&mut self, name: String
        , define: InterfaceDefine) {
        let hp = HeapPtr::alloc(define);
        self.defines.insert(name, hp);
    }

    pub fn find_define(&self, name: &str) -> Option<&HeapPtr> {
        self.defines.get(name)
    }

    pub fn length(&self) -> usize {
        self.defines.len()
    }
    
    pub fn print_defines(&self) {
        for (name, define) in self.defines.iter() {
            let v = define.pop::<InterfaceDefine>();
            println!("{}: {:?}", name, v);
            define.push(v);
        }
    }

    pub fn print_define_ptr(&self) {
        for (name, define) in self.defines.iter() {
            println!("{}: {:?}", name, define);
        }
    }

    pub fn new() -> Self {
        Self {
            defines: HashMap::new()
        }
    }
}

impl<'a> std::iter::IntoIterator for &'a DefineContainer {
    type Item = (&'a String, &'a HeapPtr);
    type IntoIter = std::collections::hash_map::Iter<'a, String, HeapPtr>;
    fn into_iter(self) -> Self::IntoIter {
        self.defines.iter()
    }
}

/*
impl<'a> std::iter::Iterator for &'a DefineContainer {
    type Item = (&'a String, &'a HeapPtr);

    fn next(&mut self) -> Option<(&'a String, &'a HeapPtr)> {
        self.defines.next()
    }
}
*/

/*
 * 模块 <-> 结构定义
 * */
pub struct InterfaceControl {
    defines: HashMap<String, DefineContainer>
}

impl InterfaceControl {
    pub fn add_define(&mut self, module_str: String
        , name: String, define: InterfaceDefine) {
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

    pub fn iter_define<F: FnMut(&String, &InterfaceDefine) -> bool>(&self
                , module_str: &str, name: &str, mut f: F) {
        let c = match self.defines.get(module_str) {
            Some(c) => c,
            None => {
                return;
            }
        };
        for (k, v) in c.into_iter() {
            let d = v.pop();
            if f(k, &d) {
                break;
            }
            v.push(d);
        }
    }

    pub fn find_define(&self, module_str: &str
        , name: &str) -> Option<&HeapPtr> {
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

    pub fn print_define_ptr(&self) {
        for (name, define) in self.defines.iter() {
            println!("{}", name);
            define.print_define_ptr();
        }
    }

    pub fn new() -> Self {
        Self {
            defines: HashMap::new()
        }
    }
}

