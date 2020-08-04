use super::{Type, PackageType, TypeAttrubute};
use libcommon::address::FunctionAddress;
use libcommon::optcode::OptCode;
use libcommon::ptr::RefPtr;
use libmacro::{FieldGet};
use std::hash::Hash;
use std::cmp::{PartialEq, Eq};
use crate::{AddressKey, AddressValue};

/*
 * 函数返回值
 * */
#[derive(Debug, Default, Clone)]
pub struct FunctionReturn {
    pub data: FunctionReturnData
}

#[derive(Debug, Clone)]
pub enum FunctionReturnDataAttr {
    RefParamIndex(u8),
    MoveIndex(u8),
    Create,
    Empty
}

impl Default for FunctionReturnDataAttr {
    fn default() -> Self {
        FunctionReturnDataAttr::Empty
    }
}

/*
 * 如果返回值是多个值, 将抽象为元组
 * */
#[derive(Debug, Clone, Default, FieldGet)]
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

/*
 * 函数参数
 * */
#[derive(Debug, Clone)]
pub struct FunctionParam {
    pub data: FunctionParamData,
    pub attr: TypeAttrubute
}

#[derive(Debug, Clone)]
pub enum FunctionParamAddrAttr {
    /*
     * Move / Ref / Ptr
     * */
    Move,
    Ref,
    Ptr
}

#[derive(Debug, Clone, FieldGet)]
pub struct FunctionParamDataItem {
    pub typ: Type,
    pub addr_attr: FunctionParamAddrAttr
}

#[derive(Debug, Clone)]
pub enum FunctionParamData {
    /*
     * 其实可以写成一个, 之所以分开, 是因为如果只有一个参数, 没必要构建一个Vec, 提高效率,
     * 降低内存消耗
     * */
    Single(FunctionParamDataItem),
    Multi(Vec<FunctionParamDataItem>)
}

impl FunctionParam {
    pub fn new(data: FunctionParamData
        , attr: TypeAttrubute) -> Self {
        Self {
            data: data,
            attr: attr
        }
    }
}

impl FunctionParamDataItem {
    pub fn new(typ: Type) -> Self {
        Self {
            typ: typ,
            addr_attr: FunctionParamAddrAttr::Move
        }
    }
}

/*
 * 函数声明
 * */
#[derive(Debug, Clone)]
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
    pub optcode: OptCode,
    /*
     * 预处理
     * */
    // pub prepare: Option<>
}

#[derive(Debug, FieldGet)]
pub struct AddressFunctionDefine {
    pub addr: FunctionAddress
}

impl AddressFunctionDefine {
    pub fn new(addr: FunctionAddress) -> Self {
        Self {
            addr: addr
        }
    }
}

/*
 * 函数
 * */
#[derive(Debug, FieldGet)]
pub struct Function {
    pub func_statement: FunctionStatement,
    pub func_define: FunctionDefine
}

impl Function {
    pub fn new(statement: FunctionStatement, define: FunctionDefine) -> Self {
        Self {
            func_statement: statement,
            func_define: define
        }
    }
}

/*
 * 查找函数结果
 * */
#[derive(Debug)]
pub enum FindFunctionResult<'a> {
    Success(FindFuncSuccess<'a>),
    NotFound,
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
    pub typ: Option<&'a Type>,
    pub package_typ: Option<&'a PackageType>,
    pub func_str: &'a str,
    /*
     * 当前的 mod, 用于类型中方法的重载
     * */
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
    pub typ: Option<&'a Type>,
    pub package_typ: Option<&'a PackageType>,
    pub func_str: String,
    pub module_str: String
}

pub type FindFunctionHandle = RefPtr;

pub trait FunctionControlInterface {
    fn is_exists(&self, context: &FindFunctionContext) -> (bool, FindFunctionHandle);
    fn find_function<'a>(&'a self, context: &FindFunctionContext
        , handle: &'a Option<FindFunctionHandle>) -> FindFunctionResult;
    fn add_function(&mut self, context: AddFunctionContext
        , handle: Option<FindFunctionHandle>, func: Function) -> AddFunctionResult;
}

/*
 * 在整个编译单元中唯一的 函数 key
 * */
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct FunctionKey {
    package_index: u64,
    func_name: String
}

#[derive(Debug, Clone)]
pub enum CallFunctionParamAddr {
    /*
     * 固定参数
     * */
    Fixed(AddressValue),
    Lengthen
}

mod function_statement;
pub mod splice;
pub mod consts;
pub mod format;


