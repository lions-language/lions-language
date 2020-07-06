use super::{PrimevalControl, FinderMap, PrimevalMethod
    , FindMethodResult, Panic, AddMethodResult
    , PrimevalMethodBindValue
    , primeval_method};
use libcommon::module::{ModuleKey};
use libcommon::address::FunctionAddress;
use libcommon::function::{FunctionKey};

impl<M> PrimevalControl<M>
    where M: FinderMap {
    pub fn find_method(&self, method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindMethodResult {
        match primeval_method(&method.func_key) {
            Some(v) => {
                /*
                 * 可能是:
                 * 1. 重写的原生方法
                 * 2. 原生方法
                 * */
                return self.find_method_from_override(method, module_key, v);
            },
            None => {
                /*
                 * 不属于任何原生方法
                 *  => 一定不在 override_map 中, 可能在 define_map 中
                 * */
                return self.find_method_from_define(method, module_key);
            }
        }
    }

    fn find_method_from_define(&self, method: &PrimevalMethod
        , module_key: &ModuleKey)
        -> FindMethodResult {
        let r = self.context(method).define_map.find_module_method(module_key, method.function_key());
        match r {
            Some(addr) => {
                /*
                 * 模块中找到了 => 返回找到的地址, 提供给后续处理
                 * */
                FindMethodResult::Address(addr)
            },
            None => {
                /*
                 * 在模块方法中没找到 => 没有重写, 可能在没有模块信息的方法集合中
                 * 检测是否在 不含有模块的方法集合中
                 * */
                match self.context(method).define_map.find_method(
                    method.function_key()) {
                    Some(addr) => {
                        FindMethodResult::Address(addr)
                    },
                    None => {
                        FindMethodResult::Panic(Panic::Undefine(None))
                    }
                }
            }
        }
    }

    fn find_method_from_override(&self, method: &PrimevalMethod
        , module_key: &ModuleKey, value: &'static PrimevalMethodBindValue)
        -> FindMethodResult {
        let r = self.context(method).define_map.find_module_method(module_key, &method.func_key);
        match r {
            Some(addr) => {
                /*
                 * 原生方法被重写了
                 * 重写了原生方法
                 *  => 根据找到的地址进行后续处理
                 * */
                FindMethodResult::Address(addr)
            },
            None => {
                /*
                 * 原生方法没有被重写
                 *  => 调用原生
                 * */
                FindMethodResult::SingleOptCode(&value.single_optcode)
            }
        }
    }

    pub fn add_method(&mut self, method: &PrimevalMethod, module_key: &ModuleKey
        , addr: FunctionAddress) -> AddMethodResult {
        match primeval_method(&method.func_key) {
            Some(_) => {
                /*
                 * 一定要重写原生方法
                 * 判断当前模块是否已经重写了
                 * */
                return self.add_method_to_module_method(method, module_key, addr);
            },
            None => {
                /*
                 * 先检测是否在非模块列表中定义过
                 * 如果没有定义过, 说明是第一次定义
                 * 如果定义过, 那么说明可能是需要重写的(具体是否是重写, 还需要在
                 * 含有模块信息的集合中查找)
                 * */
                match self.context(method).define_map.find_method(
                    method.function_key()) {
                    Some(_) => {
                        /*
                         * 查看当前模块是否定义
                         * */
                        return self.add_method_to_module_method(method, module_key, addr);
                    },
                    None => {
                        /*
                         * 第一次定义 => 写入 method 集合中
                         * */
                        self.context_mut(method).define_map.insert_method(
                            method.function_key(), addr);
                    }
                }
            }
        }
        AddMethodResult::Success
    }

    pub fn add_method_to_module_method(&mut self, method: &PrimevalMethod, module_key: &ModuleKey
        , addr: FunctionAddress) -> AddMethodResult {
        match self.context(method).define_map.find_module_method(
            module_key, method.function_key()) {
            Some(address) => {
                /*
                 * 判断地址是自身定义的, 还是引用其他模块的
                 * */
                match address {
                    FunctionAddress::ReferencesDefine(_) => {
                        /*
                         * 只是引用的其他的模块的, 当前模块却没有定义, 这种情况是允许定义的
                         * */
                        self.context_mut(method).define_map.insert_module_method(
                            module_key, method.function_key(), addr);
                    },
                    FunctionAddress::Define(_) => {
                        /*
                         * 当前模块已经定义过了 => 报错
                         * */
                        return AddMethodResult::Panic(Panic::AlreadyDefine);
                    }
                }
            },
            None => {
                /*
                 * 当前模块没有定义 => 直接写入
                 * */
                self.context_mut(method).define_map.insert_module_method(
                    module_key, method.function_key(), addr);
            }
        }
        AddMethodResult::Success
    }

    /*
    pub fn find_method(&self, method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindMethodResult {
        match method {
            PrimevalMethod::Matched(_) => {
                /*
                 * 可能是:
                 * 1. 重写的原生方法
                 * 2. 原生方法
                 * */
                return self.find_method_from_override(method, module_key);
            },
            PrimevalMethod::RightNotMatched(_) => {
                /*
                 * 不属于任何原生方法
                 *  => 一定不在 override_map 中, 可能在 define_map 中
                 * */
                return self.find_method_from_define(method, module_key);
            }
        }
    }

    pub fn add_method(&mut self, method: &PrimevalMethod, module_key: &ModuleKey
        , addr: FunctionAddress) -> AddMethodResult {
        match method {
            PrimevalMethod::Matched(_) => {
                /*
                 * 一定要重写原生方法
                 * 判断当前模块是否已经重写了
                 * */
                return self.add_method_to_module_method(method, module_key, addr);
            },
            PrimevalMethod::RightNotMatched(_) => {
                /*
                 * 先检测是否在非模块列表中定义过
                 * 如果没有定义过, 说明是第一次定义
                 * 如果定义过, 那么说明可能是需要重写的(具体是否是重写, 还需要在
                 * 含有模块信息的集合中查找)
                 * */
                match self.context(method).define_map.find_method(
                    method.function_key()) {
                    Some(_) => {
                        /*
                         * 查看当前模块是否定义
                         * */
                        return self.add_method_to_module_method(method, module_key, addr);
                    },
                    None => {
                        /*
                         * 第一次定义 => 写入 method 集合中
                         * */
                        self.context_mut(method).define_map.insert_method(
                            method.function_key(), addr);
                    }
                }
            }
        }
        AddMethodResult::Success
    }

    pub fn add_method_to_module_method(&mut self, method: &PrimevalMethod, module_key: &ModuleKey
        , addr: FunctionAddress) -> AddMethodResult {
        match self.context(method).define_map.find_module_method(
            module_key, method.function_key()) {
            Some(address) => {
                /*
                 * 判断地址是自身定义的, 还是引用其他模块的
                 * */
                match address {
                    FunctionAddress::ReferencesDefine(_) => {
                        /*
                         * 只是引用的其他的模块的, 当前模块却没有定义, 这种情况是允许定义的
                         * */
                        self.context_mut(method).define_map.insert_module_method(
                            module_key, method.function_key(), addr);
                    },
                    FunctionAddress::Define(_) => {
                        /*
                         * 当前模块已经定义过了 => 报错
                         * */
                        return AddMethodResult::Panic(Panic::AlreadyDefine);
                    }
                }
            },
            None => {
                /*
                 * 当前模块没有定义 => 直接写入
                 * */
                self.context_mut(method).define_map.insert_module_method(
                    module_key, method.function_key(), addr);
            }
        }
        AddMethodResult::Success
    }

    fn find_method_from_define(&self, method: &PrimevalMethod
        , module_key: &ModuleKey)
        -> FindMethodResult {
        let r = self.context(method).define_map.find_module_method(module_key, method.function_key());
        match r {
            Some(addr) => {
                /*
                 * 模块中找到了 => 返回找到的地址, 提供给后续处理
                 * */
                FindMethodResult::Address(addr)
            },
            None => {
                /*
                 * 在模块方法中没找到 => 没有重写, 可能在没有模块信息的方法集合中
                 * 检测是否在 不含有模块的方法集合中
                 * */
                match self.uint32_method.define_map.find_method(
                    method.function_key()) {
                    Some(addr) => {
                        FindMethodResult::Address(addr)
                    },
                    None => {
                        FindMethodResult::Panic(Panic::Undefine(None))
                    }
                }
            }
        }
    }

    fn find_method_from_override(&self, method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindMethodResult {
        let r = self.context(method).define_map.find_module_method(module_key, method.function_key());
        match r {
            Some(addr) => {
                /*
                 * 原生方法被重写了
                 * 重写了原生方法
                 *  => 根据找到的地址进行后续处理
                 * */
                FindMethodResult::Address(addr)
            },
            None => {
                /*
                 * 原生方法没有被重写
                 *  => 调用原生
                 * */
                FindMethodResult::SingleOptCode(method.to_primeval_opt_code())
            }
        }
    }
    */
}

