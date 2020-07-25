use libtype::instruction::Instruction;
use crate::define::{DefineObject, FunctionDefine
    , DefineType};
use std::collections::VecDeque;

pub struct DefineStack {
    ws: VecDeque<DefineObject>
}

impl DefineStack {
    pub fn enter(&mut self, obj: DefineObject) {
        self.ws.push_back(obj);
    }

    pub fn leave(&mut self) -> DefineObject {
        self.ws.pop_back().expect("should not happend")
    }

    pub fn write(&mut self, instruction: Instruction) -> bool {
        if self.ws.is_empty() {
            return false;
        }
        /*
         * 获取队列的最后一个元素 (栈顶元素)
         * */
        let obj = self.ws.back_mut().expect("should not happend");
        match DefineType::from(obj.typ_ref()) {
            DefineType::Function => {
                obj.as_mut::<FunctionDefine>().write(instruction);
            }
        }
        true
    }

    pub fn new() -> Self {
        Self {
            ws: VecDeque::new()
        }
    }
}
