use crate::memory::{Memory, MemoryValue};
use crate::data::Data;
use std::collections::VecDeque;

pub struct Stack {
    datas: VecDeque<Data>,
    recycles: Vec<usize>
}

impl Memory for Stack {
    fn alloc(&mut self, data: Data) -> MemoryValue {
        if self.recycles.is_empty() {
            /*
             * 没有被回收的地址 => 创建一个新的地址
             * */
            self.datas.push_back(data);
            MemoryValue::new(self.datas.len())
        } else {
            /*
             * 存在被回收的 => 返回回收的地址
             * */
            let index = self.recycles.remove(0);
            MemoryValue::new(index)
        }
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

impl Stack {
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            datas: VecDeque::with_capacity(cap),
            recycles: Vec::new()
        }
    }

    pub fn new() -> Self {
        Stack::with_capacity(50)
    }
}
