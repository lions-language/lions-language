use super::{Type, PackageType, TypeAttrubute};
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libcommon::optcode::OptCode;
use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetMove, NewWithAll
    , FieldGetClone};
use libresult::DescResult;
use crate::{AddressKey, AddressValue};
use crate::package::{PackageStr};
use std::hash::Hash;
use std::cmp::{PartialEq, Eq};
use std::collections::VecDeque;

/*
 * 函数返回值
 * */
#[derive(Debug, Default, Clone, FieldGet)]
pub struct FunctionReturn {
    pub data: FunctionReturnData
}

#[derive(Debug, Clone)]
pub enum FunctionReturnRefParam {
    Index(usize),
    Addr(AddressValue)
}

#[derive(Debug, Clone)]
pub enum FunctionReturnDataAttr {
    /*
     * 元组第一个位置: 参数的位置索引
     * 元组第二个位置: 参数的地址偏移
     *  如果引用的参数是 结构体中的某个字段, 那么在解析完 return 后面的表达式之后
     *  将得到地址的偏移量
     * 元组第三个位置: 变长参数的偏移
     * */
    RefParam(FunctionReturnRefParam),
    MoveIndex(usize),
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
#[derive(Debug, Clone, Default, FieldGet
    , NewWithAll, FieldGetClone)]
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

#[derive(Debug, Clone, FieldGet, FieldGetMove
    , NewWithAll, Default)]
pub struct CallFunctionReturnData {
    addr_value: AddressValue,
    /*
     * 是否需要对返回值分配内存
     * */
    is_alloc: bool
}


/*
 * 函数参数
 * */
#[derive(Debug, Clone, FieldGet)]
pub struct FunctionParam {
    pub data: FunctionParamData
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

#[derive(Debug, Clone, FieldGet, NewWithAll
    , FieldGetClone)]
pub struct FunctionParamDataItem {
    pub typ: Type,
    pub typ_attr: TypeAttrubute,
    /*
     * 是否是变长参数
     * */
    pub lengthen_attr: FunctionParamLengthenAttr,
    /*
     * 该字段决定: 当函数调用时, 如果传入的参数和要求的参数类型不匹配, 是否自动调用 to_#type 方法
     * */
    pub is_auto_call_totype: bool,
    pub is_check_func_call_param_typ_attr: bool
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
            , FunctionParamLengthenAttr::Fixed
            , false, true)
    }

    pub fn new_with_lengthen(typ: Type
        , typ_attr: TypeAttrubute
        , lengthen_attr: FunctionParamLengthenAttr) -> Self {
        FunctionParamDataItem::new_with_all(typ
            , typ_attr
            , lengthen_attr
            , false, true)
    }

    pub fn new_lengthen(typ: Type, typ_attr: TypeAttrubute) -> Self {
        FunctionParamDataItem::new_with_all(typ
            , typ_attr
            , FunctionParamLengthenAttr::Lengthen
            , false, true)
    }

    pub fn new_lengthen_auto_call_totype(typ: Type
        , typ_attr: TypeAttrubute
        , is_auto_call_totype: bool
        , is_check_func_call_param_typ_attr: bool) -> Self {
        FunctionParamDataItem::new_with_all(typ
            , typ_attr
            , FunctionParamLengthenAttr::Lengthen
            , is_auto_call_totype
            , is_check_func_call_param_typ_attr)
    }
}

/*
 * 函数声明
 * */
#[derive(Debug, Clone, FieldGet, FieldGetClone)]
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
    statement_str: Option<String>
}

impl FunctionStatement {
    pub fn get_func_param_len(&self) -> usize {
        match &self.func_param {
            Some(pd) => {
                match pd.data_ref() {
                    FunctionParamData::Single(_) => {
                        1
                    },
                    FunctionParamData::Multi(ps) => {
                        ps.len()
                    }
                }
            },
            None => {
                0
            }
        }
    }
}

/*
 * 函数定义
 * */
#[derive(Debug, Clone)]
pub enum FunctionDefine {
    Optcode(OptcodeFunctionDefine),
    Address(AddressFunctionDefine)
}

impl FunctionDefine {
    pub fn new_invalid_addr() -> Self {
        FunctionDefine::Address(
            AddressFunctionDefine::new(
                FunctionAddress::Define(
                    libcommon::address::FunctionAddrValue::new_invalid())))
    }

    pub fn new_addr(addr_value: FunctionAddrValue) -> Self {
        FunctionDefine::Address(
            AddressFunctionDefine::new(
                FunctionAddress::Define(
                    addr_value)))
    }
}

type OptcodeFunctionDefinePrepareFn = fn(ptr: RefPtr) -> DescResult;

#[derive(Debug, Clone, FieldGet)]
pub struct OptcodeFunctionDefine {
    pub optcode: OptCode,
    /*
     * 预处理
     * */
    // pub prepare_fn: Option<OptcodeFunctionDefinePrepareFn>
}

#[derive(Debug, Clone, FieldGet)]
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
    pub func_name: &'a str,
    pub typ: Option<&'a Type>,
    pub package_str: PackageStr,
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
pub struct AddFunctionContext {
    /*
     * 通过typ 区别应该存储在哪个对象中
     * */
    pub func_name: String,
    pub typ: Option<Type>,
    pub package_str: PackageStr,
    pub func_str: String,
    pub module_str: String,
    /*
     * 是否支持重载(不检测参数类型)
     *  1. 默认是 true, 也就是支持重载, 只有特殊标记的函数才被设置为 false (可能是内置函数,
     *     也可能是被标记的自定义函数)
     *  2. 如果函数参数中含有变长参数, 将无法进行重载, 所以当检测到含有变长参数时,
     *     该参数一定是false
     * */
    pub is_overload: bool
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


