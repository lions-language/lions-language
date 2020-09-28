use libtype::instruction::{Jump, Instruction};
use libtype::function::FunctionStatement;
use libcommon::address::{FunctionAddrValue};
use libcommon::ptr::{RefPtr, HeapPtr};
use crate::define::{FunctionDefine, FunctionDefineObject
    , DefineType};
use crate::define::to_be_filled::function::{FuncToBeFilled};
use crate::define_stream::{DefineItem, DefineItemObject};

impl FunctionDefineObject {
    pub fn new(define: FunctionDefine) -> Self {
        Self(HeapPtr::alloc_with_typ(define, DefineType::Function.into()))
    }

    pub fn get(&self) -> Box<FunctionDefine> {
        self.0.pop::<FunctionDefine>()
    }

    pub fn restore(&self, v: Box<FunctionDefine>) {
        self.0.push::<FunctionDefine>(v)
    }

    pub fn free(&self) {
        self.0.free::<FunctionDefine>();
    }

    pub fn ptr_clone(&self) -> HeapPtr {
        self.0.clone()
    }
}

impl FunctionDefine {
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
     * 用当前的索引更新参数索引
     * */
    pub fn update_after_param_index_use_current(&mut self) {
        self.after_param_index = self.index();
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

    pub fn new(statement: FunctionStatement
        , define_item: DefineItemObject) -> Self {
        Self {
            statement: statement,
            define_item: define_item,
            after_param_index: 0
        }
    }

    pub fn func_addr_value(&self) -> FunctionAddrValue {
        FunctionAddrValue::new(self.index(), self.length())
    }
    /*
    pub fn write(&mut self, instruction: Instruction) {
        /*
         * 将指令先缓存下来, 全部完成后写入到文件
         * */
        self.define_item.as_mut::<DefineStream>().write(instruction);
        self.length += 1;
    }

    pub fn new(start_pos: usize, statement: FunctionStatement
        , define_item: RefPtr) -> Self {
        Self {
            start_pos: start_pos,
            length: 0,
            statement: statement,
            to_be_filled: FuncToBeFilled::new(),
            define_item: define_item
        }
    }
    */
}

