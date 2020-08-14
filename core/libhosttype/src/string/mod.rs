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
    static ref STR_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "str:+(&str,&str)" => 0,
            "str:+(&create str,&str)" => 1,
            "str:+(&mut str,&str)" => 2,
            "str:+(&mut str,str)" => 3,
        }
    };
    /*
     * &str + &str -> &create str
     * */
    static ref REF_STR_PLUS_OPERATOR_REF_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::Ref
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str)))
                    , TypeAttrubute::CreateRef
                    , FunctionReturnDataAttr::Create
                    ),
                ),
            Some(Type::new_without_attr(
                TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefStrPlusOperatorRefStr
        })
    };
    /*
     * &create str + &str -> &mut str
     * */
    static ref CREATE_REF_STR_PLUS_OPERATOR_REF_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::CreateRef
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str)))
                    , TypeAttrubute::MutRef
                    , FunctionReturnDataAttr::RefParamIndex(0)
                    )
                ),
            Some(Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Str))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::CreateRefStrPlusOperatorRefStr
        })
    };
    /*
     * &mut str + &str -> &mut str
     * */
    static ref MUT_REF_STR_PLUS_OPERATOR_REF_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::MutRef
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::Ref
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str)))
                    , TypeAttrubute::MutRef
                    , FunctionReturnDataAttr::RefParamIndex(0)
                    )
                ),
            Some(Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Str))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::MutRefStrPlusOperatorRefStr
        })
    };
    /*
     * &mut str + str -> &mut str
     * */
    static ref MUT_REF_STR_PLUS_OPERATOR_MOVE_STR_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_PLUS_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Multi(
                    vec![FunctionParamDataItem::new(
                        Type::new_without_attr(
                            TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::MutRef
                    ), FunctionParamDataItem::new(
                        Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str)))
                        , TypeAttrubute::Move
                    )])
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new_without_attr(
                        TypeValue::Primeval(Primeval::new(
                            PrimevalType::Str)))
                    , TypeAttrubute::MutRef
                    , FunctionReturnDataAttr::RefParamIndex(0)
                    )
                ),
            Some(Type::new_without_attr(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Str))))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::MutRefStrPlusOperatorMoveStr
        })
    };

    static ref FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(STR_METHOD.len());
        v.push(&*REF_STR_PLUS_OPERATOR_REF_STR_FUNCTION);
        v.push(&*CREATE_REF_STR_PLUS_OPERATOR_REF_STR_FUNCTION);
        v.push(&*MUT_REF_STR_PLUS_OPERATOR_REF_STR_FUNCTION);
        v.push(&*MUT_REF_STR_PLUS_OPERATOR_MOVE_STR_FUNCTION);
        v
    };
}

pub fn get_method(func_str: &str) -> Option<&'static Function> {
    let index = match STR_METHOD.get(func_str) {
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

