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
        let right_expr_value = take_value_top!(self);
        let left_expr_value = take_value_top!(self);
        DescResult::Success
    }
}

