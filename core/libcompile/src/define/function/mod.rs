use libtype::instruction::Instruction;
use libtype::function::FunctionStatement;
use libcommon::ptr::RefPtr;
use crate::define::FunctionDefine;
use crate::define::to_be_filled::function::{FuncToBeFilled};
use crate::define_stream::{DefineStream};

impl FunctionDefine {
    pub fn write(&mut self, instruction: Instruction) {
        /*
         * 将指令先缓存下来, 全部完成后写入到文件
         * */
        self.define_stream.as_mut::<DefineStream>().write(instruction);
    }

    pub fn length_add(&mut self, n: usize) {
        self.length += n;
    }

    pub fn new(start_pos: usize, statement: FunctionStatement
        , define_stream: RefPtr) -> Self {
        Self {
            start_pos: start_pos,
            length: 0,
            statement: statement,
            to_be_filled: FuncToBeFilled::new(),
            define_stream: define_stream
        }
    }
}

