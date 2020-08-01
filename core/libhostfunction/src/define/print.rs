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

lazy_static!{
    /*
     * println
     * */
    pub static ref PRINTLN: Function = Function{
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
                    TypeAttrubute::Ref
                )),
            FunctionReturn::new(
                FunctionReturnData::new_with_attr(
                    Type::new(TypeValue::Primeval(Primeval::new(
                            PrimevalType::Uint16))
                            , TypeAttrubute::Move)
                    , FunctionReturnDataAttr::Create
                    ),
                ),
            Some(Type::new(TypeValue::Primeval(Primeval::new(
                        PrimevalType::Uint8))
                        , TypeAttrubute::Ref))
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::RefUint8PlusOperatorRefUint8
        })
    };
}
