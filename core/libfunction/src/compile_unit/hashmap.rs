use libtype::function::{Function
    , FindFunctionHandle};
use std::collections::HashMap;

struct FunctionSet {
    funcs: HashMap<String, Function>
}

pub struct Container {
    mods: HashMap<String, FunctionSet>
}

enum HandleType {
    FunctionSet,
    Function
}

impl std::convert::From<u8> for HandleType {
    fn from(v: u8) -> Self {
        match v {
            0 => {
                HandleType::FunctionSet
            },
            1 => {
                HandleType::Function
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
}

impl std::convert::From<&u8> for HandleType {
    fn from(v: &u8) -> Self {
        match v {
            &0 => {
                HandleType::FunctionSet
            },
            &1 => {
                HandleType::Function
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
}

impl std::convert::Into<u8> for HandleType {
    fn into(self) -> u8 {
        match self {
            HandleType::FunctionSet => {
                0
            },
            HandleType::Function => {
                1
            }
        }
    }
}

impl Container {
    pub fn is_exists(&self, module_str: &str, func_name: &str
        , func_str: &str) -> (bool, FindFunctionHandle) {
        match self.mods.get(module_str) {
            Some(m) => {
                match m.funcs.get(func_name) {
                    Some(f) => {
                        (true
                         , FindFunctionHandle::from_ref_typ::<Function>(
                             f, HandleType::Function.into()))
                    },
                    None => {
                        match m.funcs.get(func_str) {
                            Some(f) => {
                                (true
                                 , FindFunctionHandle::from_ref_typ::<Function>(
                                     f, HandleType::Function.into()))
                            },
                            None => {
                                (false
                                 , FindFunctionHandle::from_ref_typ::<FunctionSet>(
                                     m, HandleType::FunctionSet.into()))
                            }
                        }
                    }
                }
            },
            None => {
                (false, FindFunctionHandle::new_null())
            }
        }
    }

    pub fn find<'a, 'b: 'a>(&'b self, module_str: &str, func_name: &str
        , func_str: &str
        , handle: &'a Option<FindFunctionHandle>) -> Option<&'a Function> {
        match handle {
            Some(h) => {
                if h.is_null() {
                    None
                } else {
                    match HandleType::from(h.typ_ref()) {
                        HandleType::FunctionSet => {
                            h.as_ref::<FunctionSet>().funcs.get(func_str)
                        },
                        HandleType::Function => {
                            Some(h.as_ref::<Function>())
                        }
                    }
                }
            },
            None => {
                match self.mods.get(module_str) {
                    Some(m) => {
                        /*
                         * 首先通过 func_name 查找
                         * 保证可以找到那些不需要重载的函数被找到
                         * */
                        match m.funcs.get(func_name) {
                            Some(f) => {
                                Some(f)
                            },
                            None => {
                                m.funcs.get(func_str)
                            }
                        }
                    },
                    None => {
                        None
                    }
                }
            }
        }
    }

    fn first_add(&mut self, module_str: String, func_str: String
        , func: Function) {
        let mut funcs = HashMap::new();
        funcs.insert(func_str, func);
        self.mods.insert(module_str, FunctionSet{
            funcs: funcs
        });
    }

    pub fn add(&mut self, module_str: String,  func_str: String
        , handle: Option<FindFunctionHandle>, func: Function) {
        match handle {
            Some(mut h) => {
                /*
                 * 之前调用过 is_exists 方法
                 * */
                if h.is_null() {
                    /*
                     * 模块都不存在 => 模块也需要一起需写入
                     * */
                    self.first_add(module_str, func_str, func);
                } else {
                    match HandleType::from(h.typ_ref()) {
                        HandleType::FunctionSet => {
                            /*
                             * 找到了模块, 直接往模块中写入
                             * */
                            h.as_mut::<FunctionSet>().funcs.insert(func_str, func);
                        },
                        _ => {
                            panic!("should not happend");
                        }
                    }
                }
            },
            None => {
                /*
                 * 之前没有调用过 is_exists 方法
                 *  => 依次判断
                 * */
                match self.mods.get_mut(&module_str) {
                    Some(m) => {
                        /*
                         * 存在 module
                         * */
                        m.funcs.insert(func_str, func);
                    },
                    None => {
                        /*
                         * 不存在 module
                         * */
                        self.first_add(module_str, func_str, func);
                    }
                }
            }
        }
    }

    pub fn new() -> Self {
        Self {
            mods: HashMap::new()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test() {
        let container = Container::new();
        let ms = "1";
        let fs = "2";
        let (exists, handle) = container.is_exists(ms, fs);
        if !exists {
            container.find(ms, fs, &Some(handle));
        }
    }
}
