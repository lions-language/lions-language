use super::Type;
use libcommon::address::FunctionAddress;
use libcommon::optcode::OptCode;

/*
 * 函数返回值
 * */
#[derive(Debug)]
pub struct FunctionReturn {
    pub data: FunctionReturnData
}

#[derive(Debug)]
pub enum FunctionReturnDataAttr {
    RefParamIndex(u8),
    MoveIndex(u8),
    Create,
    Empty
}

/*
 * 如果返回值是多个值, 将抽象为元组
 * */
#[derive(Debug)]
pub struct FunctionReturnData {
    pub typ: Type,
    /*
     * 如果是引用类型, 需要指定引用的是哪个输入参数
     * */
    pub attr: FunctionReturnDataAttr
}

impl FunctionReturnData {
    pub fn new_with_attr(typ: Type,
        attr: FunctionReturnDataAttr) -> Self {
        Self {
            typ: typ,
            attr: attr
        }
    }

    pub fn new(typ: Type) -> Self {
        Self {
            typ: typ,
            attr: FunctionReturnDataAttr::Empty
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

impl Default for FunctionReturn {
    fn default() -> Self {
        Self {
            data: FunctionReturnData{
                typ: Type::default(),
                attr: FunctionReturnDataAttr::Empty
            }
        }
    }
}

/*
 * 函数参数
 * */
#[derive(Debug)]
pub struct FunctionParam {
    pub data: FunctionParamData
}

#[derive(Debug)]
pub struct FunctionParamDataItem {
    pub typ: Type
}

#[derive(Debug)]
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
#[derive(Debug)]
pub struct FunctionStatement {
    pub func_name: String,
    pub func_param: Option<FunctionParam>,
    /*
     * 任何方法都有返回值, 如果没有任何有效的返回值, 那么返回的就是 Empty
     * */
    pub func_return: FunctionReturn,
    /*
     * 如果是类方法, 给出类型
     * */
    pub typ: Option<Type>,
    statement_str: String
}

/*
 * 函数定义
 * */
#[derive(Debug)]
pub enum FunctionDefine {
    Optcode(OptcodeFunctionDefine),
    Address(AddressFunctionDefine)
}

#[derive(Debug)]
pub struct OptcodeFunctionDefine {
    pub optcode: OptCode
}

#[derive(Debug)]
pub struct AddressFunctionDefine {
    pub addr: FunctionAddress
}

/*
 * 函数
 * */
#[derive(Debug)]
pub struct Function {
    pub func_statement: FunctionStatement,
    pub func_define: FunctionDefine
}

/*
 * 查找函数结果
 * */
#[derive(Debug)]
pub enum FindFunctionResult<'a> {
    Success(FindFuncSuccess<'a>),
    Panic(String)
}

#[derive(Debug)]
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
#[derive(Debug)]
pub enum AddFunctionResult {
    Success,
    Panic(String)
}

/*
 * 查找函数上下文
 * */
#[derive(Debug)]
pub struct FindFunctionContext<'a> {
    pub typ: &'a Type,
    pub func_str: &'a str,
    pub module_str: &'a str
}

/*
 * 添加函数上下文
 * */
#[derive(Debug)]
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
pub mod consts;
pub mod format;


