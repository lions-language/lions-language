use libtype::instruction::Instruction;
use libcommon::ptr::RefPtr;
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

pub struct DefineStream {
    items: VecDeque<DefineItem>
    /*
     * TODO: 添加 header 信息, 便于在链接阶段, 替换没有定义的函数地址
     * */
}

impl DefineStream {
    pub fn alloc_item(&mut self) -> RefPtr {
        let index = self.items.len();
        self.items.push_back(DefineItem::new(index));
        let v = self.items.back().expect("should not happend");
        RefPtr::from_ref(v)
    }

    pub fn get_all_ins_mut_unchecked(&mut self, index: usize)
        -> &mut VecDeque<Instruction> {
        self.items.get_mut(index).expect("should not happend")
            .get_all_mut()
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
    item: &'a DefineItem,
    index: usize,
    length: usize
}

impl<'a> DefineBlock<'a> {
    pub fn new(item: &'a DefineItem) -> Self {
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
        match self.item.get(self.index) {
            Some(v) => {
                self.index += 1;
                // println!("{:?}", v);
                Some(RefPtr::from_ref::<Instruction>(v))
            },
            None => {
                None
            }
        }
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

