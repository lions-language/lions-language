use super::{PrimevalControl, FinderMap, PrimevalMethod
    , primeval_method};
use libcommon::module::{ModuleKey};
use libcommon::address::FunctionAddress;
use libcommon::function::{FunctionKey};
use libtype::function::{FindFunctionResult
    , AddFunctionResult, FindFuncSuccess
    , FindFuncPanic, AddFuncPanic
    , Function, FunctionDefine};

impl<M> PrimevalControl<M>
    where M: FinderMap {
    pub fn find_method(&self, method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindFunctionResult {
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
        -> FindFunctionResult {
        let r = self.context(method).define_map.find_module_method(module_key, method.function_key());
        match r {
            Some(func) => {
                /*
                 * 模块中找到了 => 返回找到的地址, 提供给后续处理
                 * */
                FindFunctionResult::Success(FindFuncSuccess::new(func))
            },
            None => {
                /*
                 * 在模块方法中没找到 => 没有重写, 可能在没有模块信息的方法集合中
                 * 检测是否在 不含有模块的方法集合中
                 * */
                match self.context(method).define_map.find_method(
                    method.function_key()) {
                    Some(func) => {
                        FindFunctionResult::Success(FindFuncSuccess::new(func))
                    },
                    None => {
                        FindFunctionResult::Panic(FindFuncPanic::Undefine(None))
                    }
                }
            }
        }
    }

    fn find_method_from_override(&self, method: &PrimevalMethod
        , module_key: &ModuleKey, value: &'static Function)
        -> FindFunctionResult {
        let r = self.context(method).define_map.find_module_method(module_key, &method.func_key);
        match r {
            Some(func) => {
                /*
                 * 原生方法被重写了
                 * 重写了原生方法
                 *  => 根据找到的地址进行后续处理
                 * */
                FindFunctionResult::Success(FindFuncSuccess::new(func))
            },
            None => {
                /*
                 * 原生方法没有被重写
                 *  => 调用原生
                 * */
                FindFunctionResult::Success(FindFuncSuccess::new(value))
            }
        }
    }

    pub fn add_method(&mut self, method: &PrimevalMethod, module_key: &ModuleKey
        , func: Function) -> AddFunctionResult {
        match primeval_method(&method.func_key) {
            Some(_) => {
                /*
                 * 一定要重写原生方法
                 * 判断当前模块是否已经重写了
                 * */
                return self.add_method_to_module_method(method, module_key, func);
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
                        return self.add_method_to_module_method(method, module_key, func);
                    },
                    None => {
                        /*
                         * 第一次定义 => 写入 method 集合中
                         * */
                        self.context_mut(method).define_map.insert_method(
                            method.function_key(), func);
                    }
                }
            }
        }
        AddFunctionResult::Success
    }

    pub fn add_method_to_module_method(&mut self, method: &PrimevalMethod, module_key: &ModuleKey
        , func: Function) -> AddFunctionResult {
        match self.context(method).define_map.find_module_method(
            module_key, method.function_key()) {
            Some(function) => {
                /*
                 * 判断地址是自身定义的, 还是引用其他模块的
                 * */
                let addr = match &function.func_define {
                    FunctionDefine::Optcode(_) => {
                        panic!("should not happend");
                    },
                    FunctionDefine::Address(v) => {
                        &v.addr
                    }
                };
                match addr {
                    FunctionAddress::ReferencesDefine(_) => {
                        /*
                         * 只是引用的其他的模块的, 当前模块却没有定义, 这种情况是允许定义的
                         * */
                        self.context_mut(method).define_map.insert_module_method(
                            module_key, method.function_key(), func);
                    },
                    FunctionAddress::Define(_) => {
                        /*
                         * 当前模块已经定义过了 => 报错
                         * */
                        return AddFunctionResult::Panic(AddFuncPanic::AlreadyDefine);
                    }
                }
            },
            None => {
                /*
                 * 当前模块没有定义 => 直接写入
                 * */
                self.context_mut(method).define_map.insert_module_method(
                    module_key, method.function_key(), func);
            }
        }
        AddFunctionResult::Success
    }
}

