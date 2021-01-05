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
    static ref UINT8_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "uint8:+(&uint8,&uint8)" => 0,
            "uint8:+(&uint8,&uint16)" => 1,
            "uint8:to_str(&uint8)" => 2,
            "uint8:==(&uint8,&uint8)" => 3,
            "uint8:++x(&uint8)" => 4,
            "uint8:<(&uint8,&uint8)" => 5,
        }
    };
    /*
     * &uint8 + &uint8 -> uint16
     * */
    static ref REF_UINT8_PLUS_OPERATOR_REF_UINT8_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint16)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    ),
                ),
            Some(Type::new_without_attr(
                TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8PlusOperatorRefUint8
        })
    };
    /*
     * &uint8 + &uint16 -> uint16
     * */
    static ref REF_UINT8_PLUS_OPERATOR_REF_UINT16_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint16)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint16)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8PlusOperatorRefUint16
        })
    };
    /*
     * &uint8 to_str -> String
     * */
    static ref REF_UINT8_TO_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::TO_STR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
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
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8ToStr
        })
    };
    /*
     * &uint8 == &uint8 -> bool
     * */
    static ref REF_UINT8_EQUAL_EQUAL_OPERATOR_REF_UINT8_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_EQUAL_EQUAL_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Boolean)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    ),
                ),
            Some(Type::new_without_attr(
                TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8EqualEqualOperatorRefUint8
        })
    };
    /*
     * uint8:++x(&uint8)
     * */
    static ref REF_UINT8_PREFIX_PLUS_PLUS_OPERATOR: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PREFIX_PLUS_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    ))
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint8)))
                    , TypeAttrubute::Ref
                    , FunctionReturnDataAttr::RefParam(FunctionReturnRefParam::Index(0))
                    ),
                ),
            Some(Type::new_without_attr(
                TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8PrefixPlusPlus
        })
    };
    /*
     * &uint8 < &uint8 -> bool
     * */
    static ref REF_UINT8_LESS_THAN_OPERATOR_REF_UINT8_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_LESS_THAN_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Boolean)))
                    , TypeAttrubute::Move
                    , FunctionReturnDataAttr::Create
                    ),
                ),
            Some(Type::new_without_attr(
                TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8LessThanOperatorRefUint8
        })
    };

    static ref UINT8_FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(UINT8_METHOD.len());
        v.push(&*REF_UINT8_PLUS_OPERATOR_REF_UINT8_FUNCTION);
        v.push(&*REF_UINT8_PLUS_OPERATOR_REF_UINT16_FUNCTION);
        v.push(&*REF_UINT8_TO_STR_FUNCTION);
        v.push(&*REF_UINT8_EQUAL_EQUAL_OPERATOR_REF_UINT8_FUNCTION);
        v.push(&*REF_UINT8_PREFIX_PLUS_PLUS_OPERATOR);
        v.push(&*REF_UINT8_LESS_THAN_OPERATOR_REF_UINT8_FUNCTION);
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
