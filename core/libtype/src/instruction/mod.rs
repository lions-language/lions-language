use libcommon::optcode;
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libmacro::{FieldGet, FieldGetClone
    , NewWithAll, FieldGetMove};
use crate::function::{CallFunctionParamAddr
    , CallFunctionReturnData};
use crate::{AddressValue, AddressKey, Data
    , TypeAttrubute, AddressType};
use crate::package::PackageStr;
use crate::primeval::string::Str;
use std::collections::VecDeque;

#[derive(Debug, Clone, FieldGetClone
    , FieldGetMove, FieldGet, NewWithAll)]
pub struct CallPrimevalFunctionParamContext {
    typ_attr: TypeAttrubute,
    addr_type: AddressType
}

#[derive(Debug, Clone, FieldGetClone
    , FieldGetMove, FieldGet)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
    pub param_addrs: Option<Vec<CallFunctionParamAddr>>,
    pub param_context: Option<Vec<CallPrimevalFunctionParamContext>>,
    pub call_param_len: usize,
    pub return_data: CallFunctionReturnData
}

#[derive(Debug, FieldGet, Clone)]
pub struct CallFunction {
    pub package_str: PackageStr,
    pub define_addr: FunctionAddress,
    pub return_data: CallFunctionReturnData
}

#[derive(Debug, FieldGet, Clone)]
pub struct CallSelfFunction {
    pub package_str: PackageStr,
    pub func_define_addr: FunctionAddress,
    pub param_define_addr: FunctionAddress,
    pub return_data: CallFunctionReturnData
}

#[derive(Debug, FieldGet, Clone, NewWithAll
    , FieldGetMove)]
pub struct OwnershipMove {
    pub dst_addr: AddressKey,
    pub src_addr: AddressValue
}

#[derive(Debug, Clone, FieldGetClone
    , FieldGetMove, FieldGet
    , NewWithAll)]
pub struct RemoveOwnership {
    addr: AddressKey
}

#[derive(Debug, FieldGet, Clone, NewWithAll
    , FieldGetMove, FieldGetClone)]
pub struct AddressBind {
    src_addr: AddressKey,
    dst_addr: AddressValue
}

#[derive(Debug, Clone)]
pub struct VariantValue {
    pub direction: AddressValue
}

impl VariantValue {
    pub fn new(direction: AddressValue) -> Self {
        Self {
            direction: direction
        }
    }
}

#[derive(Debug, Clone)]
pub struct Uint8Static {
    pub addr: AddressKey,
    pub value: u8
}

#[derive(Debug, Clone)]
pub struct Uint16Static {
    pub addr: AddressKey,
    pub value: u16
}

#[derive(Debug, Clone)]
pub struct Uint32Static {
    pub addr: AddressKey,
    pub value: u32
}

#[derive(Debug, Clone)]
pub struct StringStatic {
    pub addr: AddressKey,
    pub value: Str
}

#[derive(Debug, Clone, FieldGet, FieldGetClone)]
pub struct StaticVariant {
    pub package_str: PackageStr,
    pub addr: AddressValue,
    pub static_addr: AddressKey
}

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetMove)]
pub struct LoadStack {
    addr: AddressValue,
    data: Data
}

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetMove, FieldGetClone)]
pub struct ReturnStmt {
    scope: usize,
    addr_value: AddressValue
}

#[derive(Debug, Clone)]
pub enum JumpType {
    Forward,
    Backward
}

impl Default for JumpType {
    fn default() -> Self {
        JumpType::Backward
    }
}

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetMove, FieldGetClone, Default)]
pub struct Jump {
    typ: JumpType,
    index: usize
}

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetMove, FieldGetClone, Default)]
pub struct AddRefParamAddr {
    addr: AddressKey,
    dst_addr: AddressValue
}

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetMove, FieldGetClone, Default)]
pub struct BlockDefine {
    addr: FunctionAddrValue
}

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetMove, FieldGetClone, Default)]
pub struct ConditionStmt {
    expr_addr: AddressValue,
    true_block: BlockDefine,
    false_block: BlockDefine
}

/*
 * 指令
 * */
#[derive(Debug, Clone)]
pub enum Instruction {
    LoadUint8Const(Uint8Static),
    LoadUint16Const(Uint16Static),
    LoadUint32Const(Uint32Static),
    LoadStringConst(StringStatic),
    LoadStack(LoadStack),
    LoadVariant(VariantValue),
    ReadStaticVariant(StaticVariant),
    CallPrimevalFunction(CallPrimevalFunction),
    CallFunction(CallFunction),
    CallSelfFunction(CallSelfFunction),
    OwnershipMove(OwnershipMove),
    AddressBind(AddressBind),
    ReturnStmt(ReturnStmt),
    Jump(Jump),
    RemoveOwnership(RemoveOwnership),
    AddRefParamAddr(AddRefParamAddr),
    ConditionStmt(ConditionStmt),
    EnterScope,
    LeaveScope,
    Invalid
}
