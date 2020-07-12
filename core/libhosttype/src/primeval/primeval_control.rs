use super::{PrimevalControl, primeval_method, PrimevalContext};
use libcommon::address::FunctionAddress;
use libtype::{Type};
use libtype::primeval::PrimevalType;
use libtype::function::{FindFunctionResult
    , AddFunctionResult, FindFuncSuccess
    , AddFuncPanic
    , Function, FunctionDefine
    , FunctionControlInterface
    , FindFunctionContext
    , AddFunctionContext};

impl FunctionControlInterface for PrimevalControl {
    fn find_function(&self, context: &FindFunctionContext) -> FindFunctionResult {
        match primeval_method(context.typ, context.func_str) {
            Some(v) => {
                /*
                 * 可能是:
                 * 1. 重写的原生方法
                 * 2. 原生方法
                 * */
                return self.find_method_from_override(context.typ
                    , context.module_str, context.func_str, v);
            },
            None => {
                /*
                 * 不属于任何原生方法
                 *  => 一定不在 override_map 中, 可能在 define_map 中
                 * */
                return self.find_method_from_define(context.typ
                    , context.module_str, context.func_str);
            }
        }
    }

    fn add_function(&mut self, context: AddFunctionContext
        , func: Function) -> AddFunctionResult {
        match primeval_method(context.typ, &context.func_str) {
            Some(_) => {
                /*
                 * 一定要重写原生方法
                 * 判断当前模块是否已经重写了
                 * */
                return self.add_method_to_module_method(context.typ, context.module_str
                    , context.func_str, func);
            },
            None => {
                /*
                 * 先检测是否在非模块列表中定义过
                 * 如果没有定义过, 说明是第一次定义
                 * 如果定义过, 那么说明可能是需要重写的(具体是否是重写, 还需要在
                 * 含有模块信息的集合中查找)
                 * */
                match self.context(context.typ).define_map.find_method(
                    &context.func_str) {
                    Some(_) => {
                        /*
                         * 查看当前模块是否定义
                         * */
                        return self.add_method_to_module_method(context.typ
                            , context.module_str, context.func_str, func);
                    },
                    None => {
                        /*
                         * 第一次定义 => 写入 method 集合中
                         * */
                        self.context_mut(context.typ).define_map.insert_method(
                            context.func_str, func);
                    }
                }
            }
        }
        AddFunctionResult::Success
    }
}

impl PrimevalControl {
    fn find_method_from_define(&self, typ: &Type, module_str: &str
        , func_str: &str)
        -> FindFunctionResult {
        let context = self.context(typ);
        let r = context.define_map.find_module_method(module_str, func_str);
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
                match context.define_map.find_method(
                    func_str) {
                    Some(func) => {
                        FindFunctionResult::Success(FindFuncSuccess::new(func))
                    },
                    None => {
                        FindFunctionResult::Panic("undefine")
                    }
                }
            }
        }
    }

    fn find_method_from_override(&self, typ: &Type, module_str: &str
        , func_str: &str, value: &'static Function)
        -> FindFunctionResult {
        let context = self.context(typ);
        let r = context.define_map.find_module_method(module_str, func_str);
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
    
    pub fn add_method_to_module_method(&mut self, typ: &Type, module_str: String
        , func_str: String, func: Function) -> AddFunctionResult {
        match self.context_mut(typ).define_map.module_exists_mut(&module_str) {
            Some(func_set) => {
                let function = match func_set.exists(&func_str) {
                    Some(f) => {
                        f
                    },
                    None => {
                        /*
                         * 模块存在, 但是模块中的方法不存在
                         * => 添加到模块中
                         * */
                        func_set.insert(func_str, func);
                        return AddFunctionResult::Success;
                    }
                };
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
                        func_set.insert(func_str, func);
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
                self.context_mut(typ).define_map.insert_module_method(
                    module_str, func_str, func);
            }
        }
        AddFunctionResult::Success
    }
    pub fn context_mut(&mut self, typ: &Type) -> &mut PrimevalContext {
        let t = match typ {
            Type::Primeval(p) => {
                &p.typ
            },
            _ => {
                /*
                 * 进入到这里一定是处理原生类型的, 所以这里不会发生
                 * */
                panic!("should not happend");
            }
        };
        match t {
            PrimevalType::Uint8 => {
                &mut self.uint8_method
            },
            PrimevalType::Uint16 => {
                &mut self.uint16_method
            },
            PrimevalType::Uint32 => {
                &mut self.uint32_method
            },
            PrimevalType::Uint64 => {
                &mut self.uint64_method
            },
            PrimevalType::Int8 => {
                &mut self.int8_method
            },
            PrimevalType::Int16 => {
                &mut self.int16_method
            },
            PrimevalType::Int32 => {
                &mut self.int32_method
            },
            PrimevalType::Int64 => {
                &mut self.int64_method
            },
            PrimevalType::Float32 => {
                &mut self.float32_method
            },
            PrimevalType::Float64 => {
                &mut self.float64_method
            },
            PrimevalType::Str => {
                &mut self.string_method
            },
            _ => {
                unimplemented!();
            }
        }
    }

    pub fn context(&self, typ: &Type) -> &PrimevalContext {
        let t = match typ {
            Type::Primeval(p) => {
                &p.typ
            },
            _ => {
                /*
                 * 进入到这里一定是处理原生类型的, 所以这里不会发生
                 * */
                panic!("should not happend");
            }
        };
        match t {
            PrimevalType::Uint8 => {
                &self.uint8_method
            },
            PrimevalType::Uint16 => {
                &self.uint16_method
            },
            PrimevalType::Uint32 => {
                &self.uint32_method
            },
            PrimevalType::Uint64 => {
                &self.uint64_method
            },
            PrimevalType::Int8 => {
                &self.int8_method
            },
            PrimevalType::Int16 => {
                &self.int16_method
            },
            PrimevalType::Int32 => {
                &self.int32_method
            },
            PrimevalType::Int64 => {
                &self.int64_method
            },
            PrimevalType::Float32 => {
                &self.float32_method
            },
            PrimevalType::Float64 => {
                &self.float64_method
            },
            PrimevalType::Str => {
                &self.string_method
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

