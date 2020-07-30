use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libtype::function::{self, FunctionStatement
    , FunctionReturn, Function
    , AddressFunctionDefine};
use crate::define::{DefineObject, FunctionDefine
    , DefineType};
use crate::compile::FunctionNamedStmtContext;
use crate::define_stream::{DefineStream};
use std::collections::VecDeque;

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

    pub fn finish_define(&mut self, obj: DefineObject) -> Function {
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
