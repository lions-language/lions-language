use libtype::instruction::{Jump, Instruction};
use libcommon::ptr::HeapPtr;
use libcommon::address::{FunctionAddrValue};
use crate::define_stream::{DefineItemObject};
use super::{BlockDefine, BlockDefineObject};

impl BlockDefineObject {
    pub fn new(define: BlockDefine) -> Self {
        Self(HeapPtr::alloc(define))
    }

    pub fn get(&self) -> Box<BlockDefine> {
        self.0.pop::<BlockDefine>()
    }

    pub fn restore(&self, v: Box<BlockDefine>) {
        self.0.push::<BlockDefine>(v)
    }

    pub fn free(&self) {
        self.0.free::<BlockDefine>();
    }

    pub fn ptr_clone(&self) -> HeapPtr {
        self.0.clone()
    }
}

impl BlockDefine {
    pub fn new(define_item: DefineItemObject) -> Self {
        Self{
            define_item: define_item
        }
    }

    pub fn write(&mut self, instruction: Instruction) {
        /*
         * 将指令先缓存下来, 全部完成后写入到文件
         * */
        let mut item = self.define_item.get();
        item.write(instruction);
        self.define_item.free(item);
    }

    pub fn set_jump(&mut self, index: usize, jump: Jump) {
        let mut item = self.define_item.get();
        item.set_jump(index, jump);
        self.define_item.free(item);
    }

    pub fn current_index(&self) -> usize {
        let item = self.define_item.get();
        let len = item.length() - 1;
        self.define_item.free(item);
        len
    }

    /*
     * item 在 define_stream 中的索引
     * */
    pub fn index(&self) -> usize {
        let item = self.define_item.get();
        let index = item.index();
        self.define_item.free(item);
        index
    }

    pub fn length(&self) -> usize {
        let item = self.define_item.get();
        let length = item.length();
        self.define_item.free(item);
        length
    }

    pub fn block_addr_value(&self) -> FunctionAddrValue {
        FunctionAddrValue::new(self.index(), self.length())
    }
}
