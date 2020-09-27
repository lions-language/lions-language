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
        self.processing_blocks.push_back(BlockDefineObject::new(def));
        let v_ptr = self.processing_blocks.back().expect("should not happend");
        DefineObject::new(v_ptr.ptr_clone())
    }

    pub fn current_block_addr_value(&self, obj: &DefineObject) -> FunctionAddrValue {
        let fd = obj.get::<BlockDefine>();
        let addr_value = fd.block_addr_value();
        obj.restore(fd);
        addr_value
    }

    pub fn finish_define(&mut self) {
        /*
         * 暂时不考虑多线程问题, 这里的 obj 就是为了以后多线程时, 可以从中间移除元素
         * (在 FunctionDefine 中存储 索引, 移除的时候根据这个索引移除元素)
         * 现在单线程的情况下, 相当于是一个 栈, 从栈顶部移除即可
         * */
        /*
         * item 在作用域结束之后会自动释放 (释放存储进去的堆内存)
         * */
        let item_ptr = self.processing_blocks.pop_back().expect("should not happend");
        item_ptr.free();
    }

    pub fn new(ds: &'a mut DefineStream) -> Self {
        Self {
            processing_blocks: VecDeque::new(),
            define_stream: ds
        }
    }
}
