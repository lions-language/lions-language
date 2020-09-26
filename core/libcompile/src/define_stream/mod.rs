use libtype::instruction::{Instruction, Jump};
use libcommon::ptr::{RefPtr, HeapPtr};
use libcommon::address::FunctionAddrValue;
use std::collections::VecDeque;

/*
 * 存储当前 crate 的所有定义(函数定义, 结构定义 ...)
 *  1. 如果内存超过一定的大小, 将引用少(需要实现函数的引用统计)的写入到文件
 * */
pub struct DefineItem{
    mem: memory::Memory,
    index: usize,
}

impl DefineItem {
    pub fn write(&mut self, instruction: Instruction) {
        // println!("{:?}", &instruction);
        self.mem.write(instruction);
    }

    pub fn set_jump(&mut self, index: usize, jump: Jump) {
        self.mem.set_jump(index, jump);
    }

    pub fn get(&self, index: usize) -> Option<&Instruction> {
        self.mem.get(index)
    }

    pub fn get_all_mut(&mut self) -> &mut VecDeque<Instruction> {
        self.mem.get_all_mut()
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn length(&self) -> usize {
        self.mem.length()
    }

    pub fn new(index: usize) -> Self {
        Self{
            mem: memory::Memory::new(),
            index: index
        }
    }
}

#[derive(Clone)]
pub struct DefineItemObject(HeapPtr);

impl DefineItemObject {
    pub fn new(item: DefineItem) -> Self {
        Self(HeapPtr::alloc::<DefineItem>(item))
    }
    pub fn get(&self) -> Box<DefineItem> {
        self.0.pop::<DefineItem>()
    }
    pub fn free(&self, item: Box<DefineItem>) {
        self.0.push::<DefineItem>(item);
    }
    pub fn length(&self) -> usize {
        let item = self.get();
        let len = item.length();
        self.free(item);
        len
    }
}

pub struct InstructionVec(RefPtr);

impl InstructionVec {
    pub fn get_mut(&mut self) -> &mut VecDeque<Instruction> {
        self.0.as_mut::<VecDeque<Instruction>>()
    }

    pub fn new(v: &mut VecDeque<Instruction>) -> Self {
        Self(RefPtr::from_ref(v))
    }
}

pub struct DefineStream {
    items: VecDeque<DefineItemObject>
    /*
     * TODO: 添加 header 信息, 便于在链接阶段, 替换没有定义的函数地址
     * */
}

impl DefineStream {
    pub fn alloc_item(&mut self) -> DefineItemObject {
        let index = self.items.len();
        self.items.push_back(DefineItemObject::new(DefineItem::new(index)));
        let v = self.items.back().expect("should not happend");
        v.clone()
    }

    /*
     * return: &mut VecDeque<Instruction>
     * */
    pub fn get_all_ins_mut_unchecked(&mut self, index: usize)
        -> InstructionVec {
        let p = self.items.get_mut(index).expect("should not happend");
        let mut item = p.get();
        let all = InstructionVec::new(item.get_all_mut());
        p.free(item);
        all
    }

    pub fn read(&mut self, addr: &FunctionAddrValue
        , is_define: bool) -> DefineBlock {
        if is_define {
            let index = addr.index_clone();
            let item = self.items.get(index).expect("should not happend");
            let block = DefineBlock::new(item);
            block
        } else {
            unimplemented!("undefine read");
        }
    }

    pub fn length(&self) -> usize {
        self.items.len()
    }

    pub fn new() -> Self {
        Self {
            items: VecDeque::new()
        }
    }
}

pub struct DefineBlock<'a> {
    item: &'a DefineItemObject,
    index: usize,
    length: usize
}

impl<'a> DefineBlock<'a> {
    pub fn new(item: &'a DefineItemObject) -> Self {
        Self {
            item: item,
            index: 0,
            length: item.length()
        }
    }
}

impl<'a> Iterator for DefineBlock<'a> {
    type Item = RefPtr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == self.length {
            return None;
        }
        let item = self.item.get();
        let ins = match item.get(self.index) {
            Some(v) => {
                self.index += 1;
                // println!("{:?}", v);
                Some(RefPtr::from_ref::<Instruction>(v))
            },
            None => {
                None
            }
        };
        self.item.free(item);
        ins
    }
}

/*
pub struct DefineStream {
    memory: memory::Memory
}

impl DefineStream {
    pub fn write(&mut self, instruction: Instruction) {
        /*
         * TODO 现阶段直接写入到内存中, 后期将用文件缓存
         * */
        println!("{:?}", &instruction);
        self.memory.write(instruction);
    }

    pub fn read(&mut self, addr: &FunctionAddrValue) -> DefineBlock {
        let pos = addr.start_pos_ref().clone();
        let length = addr.length_ref().clone() + pos;
        let block = DefineBlock{
            stream: self,
            pos: pos,
            length: length,
        };
        block
    }

    pub fn length(&self) -> usize {
        self.memory.length()
    }

    pub fn new() -> Self {
        Self {
            memory: memory::Memory::new()
        }
    }
}

pub struct DefineBlock<'a> {
    stream: &'a DefineStream,
    pos: usize,
    length: usize
}

impl<'a> Iterator for DefineBlock<'a> {
    type Item = RefPtr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.length {
            return None;
        }
        match self.stream.memory.get(self.pos) {
            Some(v) => {
                self.pos += 1;
                // println!("{:?}", v);
                Some(RefPtr::from_ref::<Instruction>(v))
            },
            None => {
                None
            }
        }
    }
}
*/

mod memory;

