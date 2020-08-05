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
            String::from(consts::PRIMEVAL_FUNCTION_PRINTLN),
            Some(FunctionParam::new(
                FunctionParamData::Single(
                    FunctionParamDataItem::new_lengthen(
                        Type::new(TypeValue::Primeval(Primeval::new(
                                PrimevalType::Str))
                                , TypeAttrubute::Ref)
                        )
                    ),
                    TypeAttrubute::Ref
                )),
            FunctionReturn::new(
                FunctionReturnData::new(
                    Type::new_without_attr(TypeValue::Empty)),
                ),
            None
        ),
        func_define: FunctionDefine::Optcode(OptcodeFunctionDefine{
            optcode: OptCode::Println
        })
    };
}
