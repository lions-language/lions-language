use libtype::{Type, TypeValue, Primeval, TypeAttrubute};
use libtype::primeval::{PrimevalType};
use libtype::function::consts;
use libtype::function::{FunctionStatement, Function
    , FunctionDefine, OptcodeFunctionDefine
    , FunctionParam, FunctionParamData, FunctionParamDataItem
    , FunctionReturn, FunctionReturnData
    , FunctionReturnDataAttr
    };
use libcommon::optcode::{OptCode};
use phf::phf_map;

/*
 * 完美 hash
 * 静态映射
 * */
lazy_static!{
    static ref UINT16_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "uint16:+(uint16,&uint8)" => 0,
            "uint16:to_str(&uint16)" => 1,
            "uint16:to_str(uint16)" => 2,
        }
    };
    /*
     * uint16 + &uint8 -> uint32
     * */
    static ref MOVE_UINT16_PLUS_OPERATOR_REF_UINT8_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint16)))
                        , TypeAttrubute::Move
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    )]),
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint32)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    ),
                ),
            Some(Type::new_without_attr(
                TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint16))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::MoveUint16PlusOperatorRefUint8
        })
    };
    /*
     * &uint16 to_str -> String
     * */
    static ref REF_UINT16_TO_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::TO_STR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint16)))
                        , TypeAttrubute::Ref
                    ))
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new(TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str))
                            , TypeAttrubute::Move)
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint16))
                        , TypeAttrubute::Ref))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint16ToStr
        })
    };
    /*
     * uint16 to_str -> String
     * */
    static ref MOVE_UINT16_TO_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::TO_STR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint16)))
                        , TypeAttrubute::Move
                    ))
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new(TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str))
                            , TypeAttrubute::Move)
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint16))
                        , TypeAttrubute::Move))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::MoveUint16ToStr
        })
    };

    static ref UINT16_FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(UINT16_METHOD.len());
        v.push(&*MOVE_UINT16_PLUS_OPERATOR_REF_UINT8_FUNCTION);
        v.push(&*REF_UINT16_TO_STR_FUNCTION);
        v.push(&*MOVE_UINT16_TO_STR_FUNCTION);
        v
    };
}

pub fn get_method(func_str: &str) -> Option<&'static Function> {
    let index = match UINT16_METHOD.get(func_str) {
        Some(index) => {
            index
        },
        None => {
            return None;
        }
    };  
    if *index > UINT16_FUNCTION_VEC.len() as u32 {
        return None;
    }   
    match UINT16_FUNCTION_VEC.get(*index as usize) {
        Some(v) => {
            Some(v)
        },
        None => {
            None
        }
    }
}
