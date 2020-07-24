use libcommon::ptr::RefPtr;
use crate::status::{CompileStatus, CompileStatusType};
use std::collections::VecDeque;

pub struct CompileStatusDispatch {
    stack: VecDeque<RefPtr>
}

impl CompileStatusDispatch {
    pub fn enter(&mut self, ptr: RefPtr) {
        /*
         * 当进入函数/结构/... 定义的时候调用
         * */
        self.stack.push_back(ptr);
    }

    pub fn leave(&mut self) -> CompileStatus {
        /*
         * 当离开定义的时候调用
         * */
        if self.stack.is_empty() {
            panic!("should not happend");
        }
        self.stack.pop_back();
        self.status()
    }

    pub fn status(&self) -> CompileStatus {
        if self.stack.len() > 0 {
            /*
             * 定义中
             * */
            CompileStatus::new(
                CompileStatusType::FunctionDefine(self.stack.back().expect("should not happend").clone()))
        } else {
            CompileStatus::new(
                CompileStatusType::Call)
        }
    }

    pub fn new() -> Self {
        Self {
            stack: VecDeque::new()
        }
    }
}
