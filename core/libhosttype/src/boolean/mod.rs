use libtype::{Type, TypeValue, Primeval, TypeAttrubute};
use libtype::primeval::{PrimevalType};
use libtype::function::consts;
use libtype::function::{FunctionStatement, Function
    , FunctionDefine, OptcodeFunctionDefine
    , FunctionParam, FunctionParamData, FunctionParamDataItem
    , FunctionReturn, FunctionReturnData
    , FunctionReturnDataAttr, FunctionReturnRefParam
    };
use libcommon::optcode::{OptCode};
use phf::phf_map;

/*
 * 完美 hash
 * 静态映射
 * */
lazy_static!{
    static ref BOOLEAN_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "boolean:to_str(&boolean)" => 0,
            "boolean:to_str(boolean)" => 1,
        }
    };
    /*
     * &boolean to_str -> String
     * */
    static ref REF_BOOLEAN_TO_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::TO_STR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Boolean)))
                        , TypeAttrubute::Ref
                    ))
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Boolean))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefBooleanToStr
        })
    };
    /*
     * boolean to_str -> String
     * */
    static ref MOVE_BOOLEAN_TO_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::TO_STR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Boolean)))
                        , TypeAttrubute::Move
                    ))
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Boolean))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefBooleanToStr
        })
    };

    static ref FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(BOOLEAN_METHOD.len());
        v.push(&*REF_BOOLEAN_TO_STR_FUNCTION);
        v.push(&*MOVE_BOOLEAN_TO_STR_FUNCTION);
        v
    };
}

pub fn get_method(func_str: &str) -> Option<&'static Function> {
    let index = match BOOLEAN_METHOD.get(func_str) {
        Some(index) => {
            index
        },
        None => {
            return None;
        }
    };  
    if *index > FUNCTION_VEC.len() as u32 {
        return None;
    }   
    match FUNCTION_VEC.get(*index as usize) {
        Some(v) => {
            Some(v)
        },
        None => {
            None
        }
    }
}

