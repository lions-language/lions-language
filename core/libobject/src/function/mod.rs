use libtype::Type;
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
    pub func_return: Option<FunctionReturn>
}

/*
 * 函数定义
 * */
pub enum FunctionDefine {
    Primeval(PrimevalFunctionDefine),
    Struct(StructFunctionDefine)
}

pub struct PrimevalFunctionDefine {
    pub optcode: OptCode
}

pub struct StructFunctionDefine {
    pub addr: FunctionAddress
}

/*
 * 函数
 * */
pub struct Function {
    pub func_statement: FunctionStatement,
    pub func_define: FunctionDefine
}

