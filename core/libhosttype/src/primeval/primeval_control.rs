use super::{PrimevalControl, FinderMap, PrimevalMethod
    , FindMethodResult, PrimevalData
    , PrimevalType, Panic};
use libcommon::module::{ModuleKey};
use libcompile::optcode::OptCode;

impl<M> PrimevalControl<M>
    where M: FinderMap {
    pub fn find_method(&self, data: PrimevalData
        , method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindMethodResult {
        match method {
            PrimevalMethod::Type(_) => {
                /*
                 * 可能是:
                 * 1. 重写的原生方法
                 * 2. 原生方法
                 * */
                return self.find_method_from_override(data, method, module_key);
            },
            PrimevalMethod::RightNotMatched(_) => {
                /*
                 * 不属于任何原生方法
                 *  => 一定不在 override_map 中, 可能在 define_map 中
                 * */
                return self.find_method_from_define(data, method, module_key);
            }
        }
    }

    fn find_method_from_define(&self, data: PrimevalData
        , method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindMethodResult {
        let (r, key) = self.uint32_method.define_map.find_module_method(module_key, method);
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
                match self.uint32_method.define_map.find_method_key(
                    &key.expect("should not happend")) {
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

    fn find_method_from_override(&self, data: PrimevalData
        , method: &PrimevalMethod, module_key: &ModuleKey)
        -> FindMethodResult {
        let (r, key) = self.uint32_method.define_map.find_module_method(module_key, method);
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
}

