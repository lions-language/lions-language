use super::{Type, PackageType, TypeAttrubute};
use libcommon::address::FunctionAddress;
use libcommon::optcode::OptCode;
use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, NewWithAll};
use libresult::DescResult;
use crate::{AddressKey, AddressValue};
use std::hash::Hash;
use std::cmp::{PartialEq, Eq};
use std::collections::VecDeque;

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
    pub typ_attr: TypeAttrubute,
    /*
     * 如果是引用类型, 需要指定引用的是哪个输入参数
     * */
    pub attr: FunctionReturnDataAttr
}

impl FunctionReturnData {
    pub fn new_with_attr(typ: Type,
        typ_attr: TypeAttrubute,
        attr: FunctionReturnDataAttr) -> Self {
        Self {
            typ: typ,
            typ_attr: typ_attr,
            attr: attr
        }
    }

    pub fn new(typ: Type, typ_attr: TypeAttrubute) -> Self {
        Self {
            typ: typ,
            typ_attr: typ_attr,
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
#[derive(Debug, Clone, FieldGet)]
pub struct FunctionParam {
    pub data: FunctionParamData
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

#[derive(Debug, Clone)]
pub enum FunctionParamLengthenAttr {
    /*
     * 变长参数
     * */
    Lengthen,
    /*
     * 固定参数
     * */
    Fixed
}

#[derive(Debug, Clone, FieldGet, NewWithAll)]
pub struct FunctionParamDataItem {
    pub typ: Type,
    pub typ_attr: TypeAttrubute,
    pub addr_attr: FunctionParamAddrAttr,
    /*
     * 是否是变长参数
     * */
    pub lengthen_attr: FunctionParamLengthenAttr,
    /*
     * 该字段决定: 当函数调用时, 如果传入的参数和要求的参数类型不匹配, 是否自动调用 to_#type 方法
     * */
    pub is_auto_call_totype: bool
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
    pub fn new(data: FunctionParamData) -> Self {
        Self {
            data: data
        }
    }
}

impl FunctionParamDataItem {
    pub fn new(typ: Type, typ_attr: TypeAttrubute) -> Self {
        FunctionParamDataItem::new_with_all(typ
            , typ_attr
            , FunctionParamAddrAttr::Move
            , FunctionParamLengthenAttr::Fixed
            , false)
    }

    pub fn new_lengthen(typ: Type, typ_attr: TypeAttrubute) -> Self {
        FunctionParamDataItem::new_with_all(typ
            , typ_attr
            , FunctionParamAddrAttr::Move
            , FunctionParamLengthenAttr::Lengthen
            , false)
    }

    pub fn new_lengthen_auto_call_totype(typ: Type
        , typ_attr: TypeAttrubute
        , is_auto_call_totype: bool) -> Self {
        FunctionParamDataItem::new_with_all(typ
            , typ_attr
            , FunctionParamAddrAttr::Move
            , FunctionParamLengthenAttr::Lengthen
            , is_auto_call_totype)
    }
}

/*
 * 函数声明
 * */
#[derive(Debug, Clone, FieldGet)]
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

type OptcodeFunctionDefinePrepareFn = fn(ptr: RefPtr) -> DescResult;

#[derive(Debug, FieldGet)]
pub struct OptcodeFunctionDefine {
    pub optcode: OptCode,
    /*
     * 预处理
     * */
    // pub prepare_fn: Option<OptcodeFunctionDefinePrepareFn>
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
    Lengthen(VecDeque<AddressValue>)
}

mod function_statement;
pub mod splice;
pub mod consts;
pub mod format;


