use super::{PrimevalMethod, PrimevalControl, FinderMap
    , PrimevalContext, PrimevalType};
use crate::number::uint32::{Uint32Method};
use libcommon::function::{FunctionKey};
use libcompile::optcode::{OptCode};

impl PrimevalMethod {
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
}

/*
 * 下面的实现写在本文件中, 是为了不容易忘记更新
 * */
impl<M: FinderMap> PrimevalControl<M> {
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

    pub fn context(&self, method: &PrimevalMethod) -> &PrimevalContext<M> {
        self.context(method)
    }
}

