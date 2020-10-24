use libresult::*;
use libgrammar::token::TokenValue;
use libtype::{Type, TypeAttrubute};
use libtype::function::{FunctionParamData, FunctionParamDataItem
        , splice::FunctionSplice, FindFunctionContext
        , FindFunctionResult, FunctionReturnDataAttr
        , FunctionReturnRefParam
        , Function, CallFunctionParamAddr
        , CallFunctionReturnData};
use libtype::{AddressType, AddressValue, TypeValue
    , AddressKey};
use libtype::package::{PackageStr};
use libcommon::ptr::{RefPtr};
use crate::compile::{Compile, Compiler, CallFunctionContext
    , AddressValueExpand, OwnershipMoveContext};
use crate::compile::value_buffer::{ValueBufferItemContext};
use crate::compile::scope::{ScopeType};
use crate::address::{Address};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn operator_equal_equal(&mut self, _value: TokenValue) -> DescResult {
        let (right_typ, right_addr, right_typ_attr, right_package_type, right_package_str, right_context)
            = take_value_top!(self, right_expr_value).fields_move();
        let (left_typ, left_addr, left_typ_attr, left_package_type, left_package_str, left_context)
            = take_value_top!(self, left_expr_value).fields_move();
        DescResult::Success
    }
}

