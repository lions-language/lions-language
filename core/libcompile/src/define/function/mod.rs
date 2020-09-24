use libtype::instruction::{Jump, Instruction};
use libtype::function::FunctionStatement;
use libcommon::address::{FunctionAddrValue};
use libcommon::ptr::RefPtr;
use crate::define::FunctionDefine;
use crate::define::to_be_filled::function::{FuncToBeFilled};
use crate::define_stream::{DefineItem};

impl FunctionDefine {
    pub fn write(&mut self, instruction: Instruction) {
        /*
         * 将指令先缓存下来, 全部完成后写入到文件
         * */
        self.define_item.as_mut::<DefineItem>().write(instruction);
    }

    pub fn set_jump(&mut self, index: usize, jump: Jump) {
        self.define_item.as_mut::<DefineItem>().set_jump(index, jump);
    }

    pub fn current_index(&self) -> usize {
        self.define_item.as_ref::<DefineItem>().length() - 1
    }

    /*
     * item 在 define_stream 中的索引
     * */
    pub fn index(&self) -> usize {
        self.define_item.as_ref::<DefineItem>().index()
    }

    pub fn length(&self) -> usize {
        self.define_item.as_ref::<DefineItem>().length()
    }

    pub fn new(statement: FunctionStatement
        , define_item: RefPtr) -> Self {
        Self {
            statement: statement,
            define_item: define_item
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

