use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libtype::function::{self, FunctionStatement
    , FunctionReturn, Function
    , FunctionReturnDataAttr
    , AddressFunctionDefine
    , FunctionParam, FunctionParamData
    , FunctionParamDataItem};
use crate::define::{DefineObject, FunctionDefine
    , DefineType};
use crate::compile::FunctionNamedStmtContext;
use crate::define_stream::{DefineStream};
use std::collections::VecDeque;

pub struct FunctionDefineDispatch<'a> {
    /*
     * 只是用于保存 FunctionDefine, 使 作用域结束后不被销毁
     * */
    processing_funcs: VecDeque<FunctionDefine>,
    define_stream: &'a mut DefineStream
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
        self.processing_funcs.push_back(def);
        let v = self.processing_funcs.back().expect("should not happend");
        let statement_ptr = RefPtr::from_ref(v.statement_ref());
        let ptr = RefPtr::from_ref_typ::<FunctionDefine>(v, DefineType::Function.into());
        (statement_ptr, DefineObject::new(ptr))
    }

    fn to_function(&self, statement: FunctionStatement
        , fd: &FunctionDefine, addr: FunctionAddrValue) -> Function {
        Function::new(statement
            , function::FunctionDefine::Address(AddressFunctionDefine::new(
                FunctionAddress::Define(addr))))
    }

    pub fn push_function_param_to_statement(&mut self
        , define_obj: &mut DefineObject
        , item: FunctionParamDataItem) {
        let fd = define_obj.ptr_mut().as_mut::<FunctionDefine>();
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
    }

    pub fn set_function_return_to_statement(&mut self
        , define_obj: &mut DefineObject
        , item: FunctionReturn) {
        let fd = define_obj.ptr_mut().as_mut::<FunctionDefine>();
        let statement = fd.statement_mut();
        *statement.func_return_mut() = item;
    }

    pub fn update_func_return_data_attr(&mut self
        , define_obj: &mut DefineObject
        , attr: FunctionReturnDataAttr) {
        let fd = define_obj.ptr_mut().as_mut::<FunctionDefine>();
        let statement = fd.statement_mut();
        *statement.func_return_mut().data_mut().attr_mut() = attr;
    }

    pub fn current_function_statement(&self) -> Option<&FunctionStatement> {
        match self.processing_funcs.back() {
            Some(item) => {
                Some(item.statement_ref())
            },
            None => {
                None
            }
        }
    }

    pub fn finish_define(&mut self, obj: &DefineObject) -> Function {
        /*
         * 暂时不考虑多线程问题, 这里的 obj 就是为了以后多线程时, 可以从中间移除元素
         * (在 FunctionDefine 中存储 索引, 移除的时候根据这个索引移除元素)
         * 现在单线程的情况下, 相当于是一个 栈, 从栈顶部移除即可
         * */
        let fd = obj.ptr_ref().as_ref::<FunctionDefine>();
        let addr = FunctionAddrValue::new(
            fd.index(), fd.length());
        let item = self.processing_funcs.pop_back().expect("should not happend");
        self.to_function(item.statement(), fd, addr)
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

/*
pub struct FunctionDefineDispatch<'a> {
    processing_funcs: VecDeque<FunctionDefine>,
    pos: usize,
    define_stream: &'a mut DefineStream
}

impl<'a> FunctionDefineDispatch<'a> {
    pub fn alloc_define(&mut self, context: FunctionNamedStmtContext) -> DefineObject {
        let def = FunctionDefine::new(self.pos
            , FunctionStatement::new(context.name(), None, FunctionReturn::default(), None)
            , RefPtr::from_ref(self.define_stream));
        /*
         * 关键点: 获取插入后的元素的引用
         * */
        self.processing_funcs.push_back(def);
        let v = self.processing_funcs.back().expect("should not happend");
        let ptr = RefPtr::from_ref_typ::<FunctionDefine>(v, DefineType::Function.into());
        DefineObject::new(ptr)
    }

    fn to_function(&self, statement: FunctionStatement
        , fd: &FunctionDefine, addr: FunctionAddrValue) -> Function {
        Function::new(statement
            , function::FunctionDefine::Address(AddressFunctionDefine::new(
                FunctionAddress::Define(addr))))
    }

    pub fn push_function_param_to_statement(&mut self
        , define_obj: &mut DefineObject
        , item: FunctionParamDataItem) {
        let fd = define_obj.ptr_mut().as_mut::<FunctionDefine>();
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
    }

    pub fn finish_define(&mut self, obj: &DefineObject) -> Function {
        /*
         * 暂时不考虑多线程问题, 这里的 obj 就是为了以后多线程时, 可以从中间移除元素
         * (在 FunctionDefine 中存储 索引, 移除的时候根据这个索引移除元素)
         * 现在单线程的情况下, 相当于是一个 栈, 从栈顶部移除即可
         * */
        let fd = obj.ptr_ref().as_ref::<FunctionDefine>();
        self.pos += fd.length_ref().clone();
        let addr = FunctionAddrValue::new(
            fd.start_pos_ref().clone(), fd.length_ref().clone());
        if fd.to_be_filled_ref().is_exist_filled() {
            /*
             * 存在待填充的
             * */
            self.to_function(fd.statement_ref().clone(), fd, addr)
        } else {
            /*
             * 不存在待填充的
             * */
            let item = self.processing_funcs.pop_back().expect("should not happend");
            self.to_function(item.statement(), fd, addr)
        }
    }

    /*
     * TODO: 在 module 编译完成后, 从 FunctionDefineDispatch 中获取待填充队列
     * 读取队列中的每一个元素, 然后填充 DefineStream 相应位置的指令
     * */

    pub fn new(ds: &'a mut DefineStream) -> Self {
        Self {
            processing_funcs: VecDeque::new(),
            pos: 0,
            define_stream: ds
        }
    }
}
*/
