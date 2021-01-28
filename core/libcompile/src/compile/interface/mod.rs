use libresult::DescResult;
use libgrammar::token::{TokenValue, TokenData};
use libgrammar::grammar::{FunctionDefineParamContext
    , FunctionDefineParamContextType
    , FunctionDefineParamMutContext
    , FunctionDefineReturnContext
    , FunctionDefineContext
    , TypeToken};
use libtype::function::{AddFunctionContext
    , FunctionParamDataItem
    , FunctionReturnData, FunctionReturn
    , FunctionStatement};
use libtype::{TypeAttrubute, Type
    , AddressKey, AddressValue
    , AddressType};
use libtype::interface::{InterfaceDefine};
use libtype::instruction::{JumpType, Jump};
use libtype::package::{PackageStr};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext
    , TypeTokenExpand};
use crate::compile::scope::vars::Variant;
use crate::compile::scope::ScopeType;
use crate::define::{DefineObject};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_interface_define_start(&mut self
        , define: &mut InterfaceDefine) -> DescResult {
        DescResult::Success
    }
}