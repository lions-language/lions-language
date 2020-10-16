use libcommon::ptr::{RefPtr};
use libtype::instruction::{Instruction, Jump};
use crate::define::{DefineObject, FunctionDefine
    , BlockDefine
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

    pub fn front_mut_unchecked(&mut self) -> &mut DefineObject {
        self.ws.front_mut().expect("should not happend")
    }

    pub fn front_unchecked(&self) -> &DefineObject {
        self.ws.front().expect("should not happend")
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
                let mut fd = obj.get::<FunctionDefine>();
                fd.set_jump(index, jump);
                obj.restore(fd);
            },
            DefineType::Block => {
                let mut bd = obj.get::<BlockDefine>();
                bd.set_jump(index, jump);
                obj.restore(bd);
            }
        }
    }

    pub fn current_index(&self) -> usize {
        let obj = self.ws.back().expect("should not happend");
        match DefineType::from(obj.ptr_ref().typ_ref()) {
            DefineType::Function => {
                let fd = obj.get::<FunctionDefine>();
                let index = fd.current_index();
                obj.restore(fd);
                index
            },
            DefineType::Block => {
                let bd = obj.get::<BlockDefine>();
                let index = bd.current_index();
                obj.restore(bd);
                index
            }
        }
    }

    pub fn update_instructure_by_index(&mut self, index: usize, ins: Instruction) {
        let obj = self.ws.back().expect("should not happend");
        match DefineType::from(obj.ptr_ref().typ_ref()) {
            DefineType::Function => {
                let mut fd = obj.get::<FunctionDefine>();
                fd.update_instructure_by_index(index, ins);
                obj.restore(fd);
            },
            DefineType::Block => {
                let mut bd = obj.get::<BlockDefine>();
                bd.update_instructure_by_index(index, ins);
                obj.restore(bd);
            }
        }
    }

    pub fn get_current_instructure_ptr(&self, index: usize) -> RefPtr {
        let obj = self.ws.back().expect("should not happend");
        match DefineType::from(obj.ptr_ref().typ_ref()) {
            DefineType::Function => {
                let fd = obj.get::<FunctionDefine>();
                let ptr = fd.get_current_instructure_ptr_unchecked(index);
                obj.restore(fd);
                ptr
            },
            DefineType::Block => {
                let mut bd = obj.get::<BlockDefine>();
                let ptr = bd.get_current_instructure_ptr_unchecked(index);
                obj.restore(bd);
                ptr
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
                let mut fd = obj.get::<FunctionDefine>();
                fd.write(instruction);
                obj.restore(fd);
            },
            DefineType::Block => {
                let mut bd = obj.get::<BlockDefine>();
                bd.write(instruction);
                obj.restore(bd);
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
