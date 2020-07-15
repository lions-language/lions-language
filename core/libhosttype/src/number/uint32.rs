use libtype::{Type, Primeval};
use libtype::primeval::{PrimevalType};
use libtype::function::consts;
use libtype::function::{FunctionStatement, Function
    , FunctionDefine, OptcodeFunctionDefine
    , FunctionParam, FunctionParamData, FunctionParamDataItem
    , FunctionReturn, FunctionReturnData
    };
use libcommon::optcode::{OptCode};
use phf::phf_map;

/*
 * 完美 hash
 * 静态映射
 * */
lazy_static!{
    static ref UINT32_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "&uint32:+(&uint32)" => 0
        }
    };
    static ref PLUS_OPERATOR_UINT32_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::Primeval(Primeval::new(PrimevalType::Uint32))
                        )
                    )
                )),
            FunctionReturn::new(
                FunctionReturnData::new(
                    Type::Primeval(Primeval::new(PrimevalType::Uint32))
                    )
                ),
            Some(Type::Primeval(Primeval::new(PrimevalType::Uint32)))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::Uint32PlusOperatorUint32
        })
    };
    static ref UINT32_FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(UINT32_METHOD.len());
        v.push(&*PLUS_OPERATOR_UINT32_FUNCTION);
        v
    };
}

pub fn get_method(func_str: &str) -> Option<&'static Function> {
    let index = match UINT32_METHOD.get(func_str) {
        Some(index) => {
            index
        },
        None => {
            return None;
        }
    };  
    if *index > UINT32_FUNCTION_VEC.len() as u32 {
        return None;
    }   
    match UINT32_FUNCTION_VEC.get(*index as usize) {
        Some(v) => {
            Some(v)
        },
        None => {
            None
        }
    }   
}
