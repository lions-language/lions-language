use libtype::instruction::{Jump, Instruction};
use libcommon::ptr::{RefPtr, HeapPtr};
use libcommon::address::{FunctionAddrValue};
use crate::define_stream::{DefineItemObject};
use crate::define::{DefineType};
use super::{BlockDefine, BlockDefineObject};

impl BlockDefineObject {
    pub fn new(define: BlockDefine) -> Self {
        Self(HeapPtr::alloc_with_typ(define, DefineType::Block.into()))
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
        self.define_item.restore(item);
    }

    pub fn set_jump(&mut self, index: usize, jump: Jump) {
        let mut item = self.define_item.get();
        item.set_jump(index, jump);
        self.define_item.restore(item);
    }

    pub fn current_index(&self) -> usize {
        let item = self.define_item.get();
        let len = item.length() - 1;
        self.define_item.restore(item);
        len
    }

    pub fn get_current_instructure_ptr_unchecked(&self, index: usize) -> RefPtr {
        let item = self.define_item.get();
        let ptr = RefPtr::from_ref(item.get(index).expect("should not happend"));
        self.define_item.restore(item);
        ptr
    }

    pub fn update_instructure_by_index(&mut self, index: usize, ins: Instruction) {
        let mut item = self.define_item.get();
        item.update_instructure_by_index(index, ins);
        self.define_item.restore(item);
    }

    /*
     * item 在 define_stream 中的索引
     * */
    pub fn index(&self) -> usize {
        let item = self.define_item.get();
        let index = item.index();
        self.define_item.restore(item);
        index
    }

    pub fn length(&self) -> usize {
        let item = self.define_item.get();
        let length = item.length();
        self.define_item.restore(item);
        length
    }

    pub fn block_addr_value(&self) -> FunctionAddrValue {
        FunctionAddrValue::new_valid(self.index(), self.length())
    }
}
