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

impl FunctionReturnDataItem {
    pub fn new(typ: Type) -> Self {
        Self {
            typ: typ
        }
    }
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
    /*
     * 其实可以写成一个, 之所以分开, 是因为如果只有一个参数, 没必要构建一个Vec, 提高效率,
     * 降低内存消耗
     * */
    Single(FunctionParamDataItem),
    Multi(Vec<FunctionParamDataItem>)
}

impl FunctionParam {
    pub fn new(data: FunctionParamData) -> Self {
        Self {
            data: data
        }
    }
}

impl FunctionParamDataItem {
    pub fn new(typ: Type) -> Self {
        Self {
            typ: typ
        }
    }
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
    Panic(&'static str)
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

/*
 * 查找函数上下文
 * */
pub struct FindFunctionContext<'a> {
    pub typ: &'a Type,
    pub func_str: &'a str,
    pub module_str: &'a str
}

/*
 * 添加函数上下文
 * */
pub struct AddFunctionContext<'a> {
    /*
     * 通过typ 区别应该存储在哪个对象中
     * */
    pub typ: &'a Type,
    pub func_str: String,
    pub module_str: String
}

pub trait FunctionControlInterface {
    fn find_function(&self, context: &FindFunctionContext) -> FindFunctionResult;
    fn add_function(&mut self, context: AddFunctionContext
        , func: Function) -> AddFunctionResult;
}

mod function_statement;
pub mod splice;


