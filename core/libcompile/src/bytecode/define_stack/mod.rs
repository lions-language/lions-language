use libtype::instruction::{Instruction, Jump};
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

    pub fn back_mut_unchecked(&mut self) -> &mut DefineObject {
        self.ws.back_mut().expect("should not happend")
    }

    pub fn back_unchecked(&self) -> &DefineObject {
        self.ws.back().expect("should not happend")
    }

    pub fn leave(&mut self) -> DefineObject {
        self.ws.pop_back().expect("should not happend")
    }

    pub fn is_empty(&self) -> bool {
        self.ws.is_empty()
    }

    pub fn set_jump(&mut self, index: usize, jump: Jump) {
        let obj = self.ws.back_mut().expect("should not happend");
        match DefineType::from(obj.ptr_ref().typ_ref()) {
            DefineType::Function => {
                let fd = obj.ptr_mut().as_mut::<FunctionDefine>();
                fd.set_jump(index, jump);
            }
        }
    }

    pub fn current_index(&self) -> usize {
        let obj = self.ws.back().expect("should not happend");
        match DefineType::from(obj.ptr_ref().typ_ref()) {
            DefineType::Function => {
                let fd = obj.ptr_ref().as_ref::<FunctionDefine>();
                fd.current_index()
            }
        }
    }

    pub fn write(&mut self, instruction: Instruction) -> bool {
        if self.ws.is_empty() {
            return false;
        }
        /*
         * 获取队列的最后一个元素 (栈顶元素)
         * */
        let obj = self.ws.back_mut().expect("should not happend");
        match DefineType::from(obj.ptr_ref().typ_ref()) {
            DefineType::Function => {
                let fd = obj.ptr_mut().as_mut::<FunctionDefine>();
                fd.write(instruction);
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
