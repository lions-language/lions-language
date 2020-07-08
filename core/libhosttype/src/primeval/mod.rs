use libcommon::module::{ModuleKey};
use libcommon::address::FunctionAddress;
use libcommon::function::FunctionKey;
use libcommon::typesof::function::{FunctionObject};
use libcommon::optcode::OptCode;
use libtype::{Type, Primeval};
use libtype::primeval::{PrimevalType};
use libtype::function::{Function, FunctionStatement
    , FunctionDefine, OptcodeFunctionDefine};
use phf::{phf_map};

pub struct PrimevalMethod {
    pub typ: PrimevalType,
    pub func_key: FunctionKey
}

pub trait FinderMap {
    /*
     * 关联类型
     * 这里使用关联类型是为了不进行二次查找
     * */
    type FunctionSet;

    fn module_exists(&self, module: &ModuleKey) -> Option<&Self::FunctionSet> {
        unimplemented!();
    }

    fn find<'a>(&self, key: &FunctionKey, set: &'a Self::FunctionSet) -> Option<&'a Function> {
        unimplemented!();
    }

    fn find_module_method(&self, module: &ModuleKey, key: &FunctionKey)
        -> Option<&Function> {
        unimplemented!();
    }

    fn find_method(&self, key: &FunctionKey) -> Option<&Function> {
        unimplemented!();
    }

    fn insert_module_method(&mut self, module: &ModuleKey, key: &FunctionKey
        , addr: Function) {
        unimplemented!();
    }

    fn insert_method(&mut self, key: &FunctionKey, addr: Function) {
        unimplemented!();
    }
}

pub struct PrimevalContext<M>
    where M: FinderMap {
    define_map: M
}

pub struct PrimevalControl<M>
    where M: FinderMap {
    int8_method: PrimevalContext<M>,
    int16_method: PrimevalContext<M>,
    int32_method: PrimevalContext<M>,
    int64_method: PrimevalContext<M>,
    uint8_method: PrimevalContext<M>,
    uint16_method: PrimevalContext<M>,
    uint32_method: PrimevalContext<M>,
    uint64_method: PrimevalContext<M>,
    float32_method: PrimevalContext<M>,
    float64_method: PrimevalContext<M>,
    string_method: PrimevalContext<M>
}

pub mod finder_map;
mod primeval_control;
mod primeval_method;

impl PrimevalMethod {
    pub fn new(typ: PrimevalType, func_obj: FunctionObject) -> Self {
        let mut key_s = String::from(typ.to_str());
        key_s.push('_');
        key_s.push_str(func_obj.function_string());
        Self {
            typ: typ,
            func_key: FunctionKey::new(key_s)
        }
    }

    pub fn from_func_key(typ: PrimevalType, func_key: FunctionKey) -> Self {
        Self {
            typ: typ,
            func_key: func_key
        }
    }
}

pub struct PrimevalMethodBindValue {
    single_optcode: OptCode
}

/*
 * 完美hash
 * 静态映射
 * */
lazy_static!{
    static ref uint32_plus_operator_uint32_function: Function = Function{
        func_statement: FunctionStatement{
            func_name: String::from("+"),
            func_param: None,
            func_return: None,
            typ: Some(Type::Primeval(Primeval::new(PrimevalType::Uint32(None))))
        },
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::Uint32PlusOperatorUint32
        })
    };

    /*
    static ref PRIMEVAL_METHOD_MAP: phf::Map<&'static str, &'static Function> = phf_map! {
        "uint32_+_uint32" => &*uint32_plus_operator_uint32_function
    };
    static ref PRIMEVAL_METHOD_MAP: phf::Map<&'static str, Function> = phf_map! {
        "uint32_+_uint32" => Function{
            func_statement: FunctionStatement{
                func_name: String::from("+"),
                func_param: None,
                func_return: None,
                typ: Some(Type::Primeval(Primeval::new(PrimevalType::Uint32(None))))
            },
            func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
                optcode: OptCode::Uint32PlusOperatorUint32
            })
        }
    };
    */
}

/*
static PRIMEVAL_METHOD_MAP: phf::Map<&'static str, Function> = phf_map! {
    "uint32_+_uint32" => Function{
        func_statement: FunctionStatement{
            func_name: String::from("+"),
            func_param: None,
            func_return: None,
            typ: Some(Type::Primeval(Primeval::new(PrimevalType::Uint32(None))))
        },
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::Uint32PlusOperatorUint32
        })
    }
};
*/

static TEST: phf::Map<&'static str, &'static str> = phf_map!{
    "1" => "2"
};

pub fn primeval_method(key: &FunctionKey) -> Option<&'static Function> {
    // PRIMEVAL_METHOD_MAP.get(key.key_ref())
    None
}

