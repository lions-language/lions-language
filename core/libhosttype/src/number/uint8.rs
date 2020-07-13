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
    static ref UINT8_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "+(uint8)" => 0,
            "+(uint16)" => 1,
        }
    };
    /*
     * uint8 + uint8
     * */
    static ref PLUS_OPERATOR_UINT8_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::Primeval(Primeval::new(PrimevalType::Uint8))
                        )
                    )
                )),
            FunctionReturn::new(
                FunctionReturnData::new(
                    Type::Primeval(Primeval::new(PrimevalType::Uint8))
                    )
                ),
            Some(Type::Primeval(Primeval::new(PrimevalType::Uint8)))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::Uint8PlusOperatorUint8
        })
    };
    /*
     * uint8 + uint16
     * */
    static ref PLUS_OPERATOR_UINT16_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::Primeval(Primeval::new(PrimevalType::Uint16))
                        )
                    )
                )),
            FunctionReturn::new(
                FunctionReturnData::new(
                    Type::Primeval(Primeval::new(PrimevalType::Uint16))
                    )
                ),
            Some(Type::Primeval(Primeval::new(PrimevalType::Uint8)))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::Uint8PlusOperatorUint16
        })
    };

    static ref UINT8_FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(UINT8_METHOD.len());
        v.push(&*PLUS_OPERATOR_UINT8_FUNCTION);
        v.push(&*PLUS_OPERATOR_UINT16_FUNCTION);
        v
    };
}

pub fn get_method(func_str: &str) -> Option<&'static Function> {
    let index = match UINT8_METHOD.get(func_str) {
        Some(index) => {
            index
        },
        None => {
            return None;
        }
    };  
    if *index > UINT8_FUNCTION_VEC.len() as u32 {
        return None;
    }   
    match UINT8_FUNCTION_VEC.get(*index as usize) {
        Some(v) => {
            Some(v)
        },
        None => {
            None
        }
    }   
}
