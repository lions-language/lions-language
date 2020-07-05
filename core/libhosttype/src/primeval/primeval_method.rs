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
    pub fn to_function_key(&self) -> FunctionKey {
        match self {
            PrimevalMethod::Type(t) => {
                match t  {
                    PrimevalType::Uint32(e) => {
                        match e {
                            Uint32Method::PlusOperatorUint32(_) => {
                                FunctionKey::Static("uint32_+_uint32")
                            }
                        }
                    }
                }
            },
            PrimevalMethod::RightNotMatched(v) => {
                let (typ, func_obj) = v;
                /*
                 * 因为右边不是原生类型, 所以不管怎么样都需要动态拼接, 所以可以统一处理
                 * */
                let mut s = String::from(typ.to_str());
                s.push_str(func_obj.function_string());
                FunctionKey::Dynamic(s)
            }
        }
    }

    pub fn to_primeval_opt_code(&self) -> OptCode {
        match self {
            PrimevalMethod::Type(t) => {
                match t {
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

    pub fn context(&self, method: &PrimevalMethod) -> &PrimevalContext<M> {
        match method {
            PrimevalMethod::Type(t) => {
                self.context_by_primeval_type(t)
            },
            PrimevalMethod::RightNotMatched(v) => {
                let (typ, _) = v;
                self.context_by_primeval_type(typ)
            }
        }
    }
}
