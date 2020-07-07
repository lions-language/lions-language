use super::{PrimevalMethod, PrimevalControl, FinderMap
    , PrimevalContext, PrimevalType};
use libcommon::function::{FunctionKey};

impl PrimevalMethod {
    pub fn function_key(&self) -> &FunctionKey {
        &self.func_key
    }
    /*
    /*
     * TODO: 优化, 在结构对象 new 的时候计算 function key(存储到成员), 因为访问要多于写入
     * 为了提高访问效率
     * */
    pub fn function_key(&self) -> &FunctionKey {
        match self {
            PrimevalMethod::Matched(t) => {
                &t.func_key
            },
            PrimevalMethod::RightNotMatched(v) => {
                /*
                 * 因为右边不是原生类型, 所以不管怎么样都需要动态拼接, 所以可以统一处理
                 * */
                &v.func_key
            }
        }
    }

    pub fn to_primeval_opt_code(&self) -> OptCode {
        match self {
            PrimevalMethod::Matched(t) => {
                match &t.typ {
                    PrimevalType::Uint32(e) => {
                        match e {
                            Uint32Method::PlusOperatorUint32(_) => {
                                OptCode::Uint32PlusOperatorUint32
                            }
                        }
                    }
                }
            },
            _ => {
                /*
                 * 原生类型的拓展方法不可能调用本方法, 因为无法获取
                 * */
                panic!("should not hapend");
            }
        }
    }
    */
}

/*
 * 下面的实现写在本文件中, 是为了不容易忘记更新
 * */
impl<M: FinderMap> PrimevalControl<M> {
    /*
    fn context_by_primeval_type(&self, typ: &PrimevalType) -> &PrimevalContext<M> {
        match typ {
            PrimevalType::Uint32(_) => {
                &self.uint32_method
            }
        }
    }

    fn context_mut_by_primeval_type(&mut self, typ: &PrimevalType) -> &mut PrimevalContext<M> {
        match typ {
            PrimevalType::Uint32(_) => {
                &mut self.uint32_method
            }
        }
    }

    pub fn context_mut(&mut self, method: &PrimevalMethod) -> &mut PrimevalContext<M> {
        match method {
            PrimevalMethod::Matched(t) => {
                self.context_mut_by_primeval_type(&t.typ)
            },
            PrimevalMethod::RightNotMatched(v) => {
                self.context_mut_by_primeval_type(&v.typ)
            }
        }
    }
    */

    pub fn context_mut(&mut self, method: &PrimevalMethod) -> &mut PrimevalContext<M> {
        match &method.typ {
            PrimevalType::Uint8(_) => {
                &mut self.uint8_method
            },
            PrimevalType::Uint16(_) => {
                &mut self.uint16_method
            },
            PrimevalType::Uint32(_) => {
                &mut self.uint32_method
            },
            PrimevalType::Uint64(_) => {
                &mut self.uint64_method
            },
            PrimevalType::Int8(_) => {
                &mut self.int8_method
            },
            PrimevalType::Int16(_) => {
                &mut self.int16_method
            },
            PrimevalType::Int32(_) => {
                &mut self.int32_method
            },
            PrimevalType::Int64(_) => {
                &mut self.int64_method
            },
            PrimevalType::Float32(_) => {
                &mut self.float32_method
            },
            PrimevalType::Float64(_) => {
                &mut self.float64_method
            },
            PrimevalType::Str(_) => {
                &mut self.string_method
            }
        }
    }

    pub fn context(&self, method: &PrimevalMethod) -> &PrimevalContext<M> {
        self.context(method)
    }
}

