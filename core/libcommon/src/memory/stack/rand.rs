use super::RandStack;
use std::collections::VecDeque;

impl<T> RandStack<T> {
    fn alloc(&mut self, data: T) -> usize {
        if self.recycles.is_empty() {
            /*
             * 没有被回收的地址 => 创建一个新的地址
             * */
            self.datas.push_back(data);
            self.datas.len() - 1
        } else {
            /*
             * 存在被回收的 => 返回回收的地址
             * */
            let index = self.recycles.remove(0);
            index
        }
    }

    fn get_unwrap(&self, index: &usize) -> &T {
        self.datas.get(index.clone()).unwrap()
    }

    fn get_mut_unwrap(&mut self, index: &usize) -> &mut T {
        self.datas.get_mut(index.clone()).unwrap()
    }

    fn free(&mut self, index: usize) {
        if index == self.datas.len() - 1 {
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
            self.recycles.push(index);
        }
    }

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

