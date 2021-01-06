use libtype::{AddressType, AddressKey
    , AddressValue};
use crate::memory::{Rand, MemoryValue};
use std::collections::HashMap;
use std::fmt::Debug;

pub struct RandStack<T> {
    datas: HashMap<usize, T>,
    recycles: Vec<usize>,
    index: usize
}

impl<T> Rand<T> for RandStack<T> {
    fn alloc(&mut self, addr_typ: AddressType, data: T) -> MemoryValue {
        if self.recycles.is_empty() {
            /*
             * 没有被回收的地址 => 创建一个新的地址
             * */
            self.datas.insert(self.index, data);
            let k = MemoryValue::new(
                AddressValue::new(addr_typ
                    , AddressKey::new_single(self.index as u64)));
            self.index += 1;
            k
        } else {
            /*
             * 存在被回收的 => 返回回收的地址
             * */
            let index = self.recycles.remove(0);
            self.datas.insert(index, data);
            // println!("get: {}", index);
            MemoryValue::new(
                AddressValue::new(addr_typ,
                    AddressKey::new_single(index as u64)))
        }
    }

    fn get_unwrap(&self, index: &MemoryValue) -> &T {
        self.datas.get(&(index.get_index_clone() as usize)).unwrap()
    }

    fn get_mut_unwrap(&mut self, index: &MemoryValue) -> &mut T {
        self.datas.get_mut(&index.get_index_clone()).unwrap()
    }

    fn get_mut(&mut self, index: &MemoryValue) -> Option<&mut T> {
        self.datas.get_mut(&index.get_index_clone())
    }

    fn take_unwrap(&mut self, index: &MemoryValue) -> T {
        let index = index.get_index_clone();
        /*
         * 添加到回收中
         * */
        // println!("take: {}", index);
        self.recycles.push(index);
        self.datas.remove(&index).expect("randstack take error")
    }

    fn free(&mut self, index: MemoryValue) {
        let index = index.get_index_clone();
        self.datas.remove(&index);
        /*
        let index = index.get_index_clone();
        if index == self.datas.len() - 1 {
            /*
             * 将要移除的是顶端元素
             *  不需要回收地址, 直接释放
             * */
            self.datas.remove(&index);
        } else {
            /*
             * 移除的是中间元素
             *  回收地址, 以备后续使用
             * */
            self.recycles.push(index);
        }
        */
    }

    fn exists(&self, index: &MemoryValue) -> bool {
        match self.datas.get(&(index.get_index_clone() as usize)) {
            Some(_) => true,
            None => false
        }
    }
}

impl<T: Debug> RandStack<T> {
    pub fn print_datas(&self) {
        for data in self.datas.iter() {
            println!("{:?}", data);
        }
    }

    pub fn print_recycles(&self) {
        for recycle in self.recycles.iter() {
            println!("{}", recycle);
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            datas: HashMap::with_capacity(cap),
            recycles: Vec::new(),
            index: 0
        }
    }

    pub fn new() -> Self {
        RandStack::with_capacity(50)
    }
}

