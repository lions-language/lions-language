use super::Type;
use libcommon::address::FunctionAddress;
use libcommon::optcode::OptCode;

/*
 * 函数返回值
 * */
pub struct FunctionReturn {
    pub data: FunctionReturnData
}

pub struct FunctionReturnDataItem {
    pub typ: Type
}

pub enum FunctionReturnData {
    Single(FunctionReturnDataItem),
    Multi(Vec<FunctionReturnDataItem>)
}

impl FunctionReturn {
    pub fn new(data: FunctionReturnData) -> Self {
        Self {
            data: data
        }
    }
}

/*
 * 函数参数
 * */
pub struct FunctionParam {
    pub data: FunctionParamData
}

pub struct FunctionParamDataItem {
    pub typ: Type
}

pub enum FunctionParamData {
    Single(FunctionParamDataItem),
    Multi(Vec<FunctionParamDataItem>)
}

/*
 * 函数声明
 * */
pub struct FunctionStatement {
    pub func_name: String,
    pub func_param: Option<FunctionParam>,
    pub func_return: Option<FunctionReturn>,
    /*
     * 如果是类方法, 给出类型
     * */
    pub typ: Option<Type>
}

/*
 * 函数定义
 * */
pub enum FunctionDefine {
    Optcode(OptcodeFunctionDefine),
    Address(AddressFunctionDefine)
}

pub struct OptcodeFunctionDefine {
    pub optcode: OptCode
}

pub struct AddressFunctionDefine {
    pub addr: FunctionAddress
}

/*
 * 函数
 * */
pub struct Function {
    pub func_statement: FunctionStatement,
    pub func_define: FunctionDefine
}

/*
 * 查找函数结果
 * */
pub enum FindFunctionResult<'a> {
    Success(FindFuncSuccess<'a>),
    Panic(FindFuncPanic)
}

pub enum FindFuncPanic {
    Undefine(Option<&'static str>),
}

pub struct FindFuncSuccess<'a> {
    pub func: &'a Function
}

impl<'a> FindFuncSuccess<'a> {
    pub fn new(func: &'a Function) -> Self {
        Self {
            func: func
        }
    }
}

/*
 * 添加函数结果
 * */
pub enum AddFunctionResult {
    Success,
    Panic(AddFuncPanic)
}

pub enum AddFuncPanic {
    AlreadyDefine
}

