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
    static ref UINT32_METHOD: phf::Map<&'static str, u32> = {
        phf_map! {
            "&uint32:+(&uint32)" => 0,
            "uint32:+(&uint8)" => 1
        }
    };
    static ref REF_UINT32_PLUS_OPERATOR_REF_UINT32_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint32))
                                , TypeAttrubute::Ref)
                        )
                    ),
                    TypeAttrubute::Move
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new(TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint32))
                            , TypeAttrubute::Move)
                        , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint32))
                        , TypeAttrubute::Ref))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint32PlusOperatorRefUint32
        })
    };
    static ref MOVE_UINT32_PLUS_OPERATOR_REF_UINT8_FUNCTION: Function = Function{
        func_statement: FunctionStatement::new(
            String::from(consts::OPERATOR_FUNCTION_NAME),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new(
                        Type::new(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Uint8))
                                , TypeAttrubute::Ref)
                        )
                    ),
                    TypeAttrubute::Move
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new(TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint64))
                            , TypeAttrubute::Move)
                        , FunctionReturnDataAttr::Create
                    )
                ),
            Some(Type::new(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint32))
                        , TypeAttrubute::Move))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::MoveUint32PlusOperatorRefUint8
        })
    };
    static ref UINT32_FUNCTION_VEC: Vec<&'static Function> = {
        let mut v = Vec::with_capacity(UINT32_METHOD.len());
        v.push(&*REF_UINT32_PLUS_OPERATOR_REF_UINT32_FUNCTION);
        v.push(&*MOVE_UINT32_PLUS_OPERATOR_REF_UINT8_FUNCTION);
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
