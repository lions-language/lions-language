use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libtype::function::{self, FunctionStatement
    , FunctionReturn, Function
    , FunctionReturnDataAttr
    , AddressFunctionDefine
    , FunctionParam, FunctionParamData
    , FunctionParamDataItem};
use crate::define::{DefineObject, FunctionDefine
    , FunctionDefineObject, DefineType};
use crate::compile::FunctionNamedStmtContext;
use crate::define_stream::{DefineStream};
use std::collections::VecDeque;
use super::{FunctionDefineDispatch};

pub struct FunctionStatementObject(RefPtr);

impl FunctionStatementObject {
    pub fn get(&self) -> &FunctionStatement {
        self.0.as_ref::<FunctionStatement>()
    }

    pub fn new(state: &FunctionStatement) -> Self {
        Self(RefPtr::from_ref::<FunctionStatement>(state))
    }
}

impl<'a> FunctionDefineDispatch<'a> {
    pub fn alloc_define(&mut self, context: FunctionNamedStmtContext) -> (RefPtr, DefineObject) {
        let (func_name, typ) = context.fields_move();
        let def = FunctionDefine::new(
            FunctionStatement::new(func_name, None, FunctionReturn::default(), typ)
            , self.define_stream.alloc_item());
        /*
         * 关键点: 获取插入后的元素的引用
         * */
        self.processing_funcs.push_back(FunctionDefineObject::new(def));
        let v_ptr = self.processing_funcs.back().expect("should not happend");
        let v = v_ptr.get();
        let statement_ptr = RefPtr::from_ref(v.statement_ref());
        v_ptr.restore(v);
        (statement_ptr, DefineObject::new(v_ptr.ptr_clone()))
    }

    fn to_function(&self, statement: FunctionStatement
        , addr: FunctionAddrValue) -> Function {
        Function::new(statement
            , function::FunctionDefine::Address(AddressFunctionDefine::new(
                FunctionAddress::Define(addr))))
    }

    pub fn push_function_param_to_statement(&mut self
        , define_obj: &mut DefineObject
        , item: FunctionParamDataItem) {
        let mut fd = define_obj.get::<FunctionDefine>();
        let statement = fd.statement_mut();
        match statement.func_param_mut() {
            Some(func_param) => {
                /*
                 * 存在参数, 需要追加
                 * */
                match func_param.data_mut() {
                    FunctionParamData::Single(data) => {
                        *statement.func_param_mut() =
                            Some(FunctionParam::new(
                                    FunctionParamData::Multi(
                                        vec![data.clone(), item])));
                    },
                    FunctionParamData::Multi(data) => {
                        data.push(item);
                    }
                }
            },
            None => {
                /*
                 * 修改之前没有参数 => 创建一个 Single
                 * */
                *statement.func_param_mut() =
                    Some(FunctionParam::new(FunctionParamData::Single(item)));
            }
        }
        define_obj.restore(fd);
    }

    pub fn set_function_return_to_statement(&mut self
        , define_obj: &mut DefineObject
        , item: FunctionReturn) {
        let mut fd = define_obj.get::<FunctionDefine>();
        let statement = fd.statement_mut();
        *statement.func_return_mut() = item;
        define_obj.restore(fd);
    }

    pub fn update_func_return_data_attr(&mut self
        , define_obj: &mut DefineObject
        , attr: FunctionReturnDataAttr) {
        let mut fd = define_obj.get::<FunctionDefine>();
        let statement = fd.statement_mut();
        *statement.func_return_mut().data_mut().attr_mut() = attr;
        define_obj.restore(fd);
    }

    pub fn current_function_statement(&self) -> Option<FunctionStatementObject> {
        match self.processing_funcs.back() {
            Some(item_ptr) => {
                let item = item_ptr.get();
                let s = Some(FunctionStatementObject::new(item.statement_ref()));
                item_ptr.restore(item);
                s
            },
            None => {
                None
            }
        }
    }

    pub fn current_function_addr_value(&self, obj: &DefineObject) -> FunctionAddrValue {
        let fd = obj.get::<FunctionDefine>();
        let addr_value = fd.func_addr_value();
        obj.restore(fd);
        addr_value
    }

    pub fn finish_define(&mut self) -> Function {
        /*
         * 暂时不考虑多线程问题, 这里的 obj 就是为了以后多线程时, 可以从中间移除元素
         * (在 FunctionDefine 中存储 索引, 移除的时候根据这个索引移除元素)
         * 现在单线程的情况下, 相当于是一个 栈, 从栈顶部移除即可
         * */
        /*
         * item 在作用域结束之后会自动释放 (释放存储进去的堆内存)
         * */
        let item_ptr = self.processing_funcs.pop_back().expect("should not happend");
        let item = item_ptr.get();
        let addr = item.func_addr_value();
        let func = self.to_function(item.statement(), addr);
        func
    }

    /*
     * TODO: 在 module 编译完成后, 从 FunctionDefineDispatch 中获取待填充队列
     * 读取队列中的每一个元素, 然后填充 DefineStream 相应位置的指令
     * */

    pub fn new(ds: &'a mut DefineStream) -> Self {
        Self {
            processing_funcs: VecDeque::new(),
            define_stream: ds
        }
    }
}

