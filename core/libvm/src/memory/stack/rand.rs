use libtype::Data;
use crate::memory::{Rand, MemoryValue};
use super::RandStack;
use std::collections::VecDeque;

impl Rand for RandStack {
    fn alloc(&mut self, data: Data) -> MemoryValue {
        if self.recycles.is_empty() {
            /*
             * 没有被回收的地址 => 创建一个新的地址
             * */
            self.datas.push_back(data);
            MemoryValue::new(self.datas.len() - 1)
        } else {
            /*
             * 存在被回收的 => 返回回收的地址
             * */
            let index = self.recycles.remove(0);
            MemoryValue::new(index)
        }
    }

    fn get_unwrap(&self, index: &MemoryValue) -> &Data {
        self.datas.get(index.get()).unwrap()
    }

    fn get_mut_unwrap(&mut self, index: &MemoryValue) -> &mut Data {
        self.datas.get_mut(index.get()).unwrap()
    }

    fn free(&mut self, index: MemoryValue) {
        if index.get() == self.datas.len() - 1 {
            /*
             * 将要移除的是顶端元素
             *  不需要回收地址, 直接释放
             * */
            self.datas.pop_back();
        } else {
            /*
             * 移除的是中间元素
             *  回收地址, 以备后续使用
             * */
            self.recycles.push(index.get());
        }
    }
}

impl RandStack {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            datas: VecDeque::with_capacity(cap),
            recycles: Vec::new()
        }
    }

    pub fn new() -> Self {
        RandStack::with_capacity(50)
    }
}

