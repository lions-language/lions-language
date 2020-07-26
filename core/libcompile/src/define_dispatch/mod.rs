use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddrValue};
use libtype::function::{FunctionStatement
    , FunctionReturn};
use crate::define::{DefineObject, FunctionDefine
    , DefineType};
use crate::compile::FunctionNamedStmtContext;
use std::collections::VecDeque;

pub struct FunctionDefineDispatch {
    processing_funcs: VecDeque<FunctionDefine>,
    pos: usize
}

impl FunctionDefineDispatch {
    pub fn alloc_define(&mut self, context: FunctionNamedStmtContext) -> DefineObject {
        let def = FunctionDefine::new(self.pos
            , FunctionStatement::new(context.name(), None, FunctionReturn::default(), None));
        /*
         * 关键点: 获取插入后的元素的引用
         * */
        self.processing_funcs.push_back(def);
        let v = self.processing_funcs.back().expect("should not happend");
        let ptr = RefPtr::from_ref_typ::<FunctionDefine>(v, DefineType::Function.into());
        DefineObject::new(ptr)
    }

    pub fn finish_define(&mut self, obj: DefineObject) {
        /*
         * 暂时不考虑多线程问题, 这里的 obj 就是为了以后多线程时, 可以从中间移除元素
         * (在 FunctionDefine 中存储 索引, 移除的时候根据这个索引移除元素)
         * 现在单线程的情况下, 相当于是一个 栈, 从栈顶部移除即可
         * */
        let fd = obj.ptr_ref().as_ref::<FunctionDefine>();
        self.pos += fd.length_ref().clone();
        self.processing_funcs.pop_back();
        // FunctionAddrValue::new(fd.start_pos_clone(), fd.length_clone())
    }

    pub fn new() -> Self {
        Self {
            processing_funcs: VecDeque::new(),
            pos: 0
        }
    }
}
