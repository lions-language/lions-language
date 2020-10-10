use libcommon::address::FunctionAddrValue;
use super::{BlockDefineDispatch};
use crate::define::{BlockDefine, DefineObject
    , BlockDefineObject};
use crate::define_stream::{DefineStream};
use std::collections::VecDeque;

impl<'a> BlockDefineDispatch<'a> {
    pub fn alloc_define(&mut self) -> DefineObject {
        /*
         * 关键点: 获取插入后的元素的引用
         * */
        let item = self.define_stream.alloc_item();
        let def = BlockDefine::new(item);
        let v_ptr = BlockDefineObject::new(def);
        DefineObject::new(v_ptr.ptr_clone())
    }

    pub fn current_block_addr_value(&self, obj: &DefineObject) -> FunctionAddrValue {
        let fd = obj.get::<BlockDefine>();
        let addr_value = fd.block_addr_value();
        obj.restore(fd);
        addr_value
    }

    pub fn finish_define(&mut self, define_obj: &DefineObject) -> FunctionAddrValue {
        /*
         * 释放 BlockDefine 对象 (get 后 rust自动释放)
         * */
        let block_define = define_obj.get::<BlockDefine>();
        block_define.block_addr_value().clone()
    }

    pub fn new(ds: &'a mut DefineStream) -> Self {
        Self {
            define_stream: ds
        }
    }
}
