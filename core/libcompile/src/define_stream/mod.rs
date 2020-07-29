use libtype::instruction::Instruction;
use libcommon::ptr::RefPtr;
use libcommon::address::FunctionAddrValue;

/*
 * 存储当前 crate 的所有定义(函数定义, 结构定义 ...)
 *  1. 如果内存超过一定的大小, 将引用少(需要实现函数的引用统计)的写入到文件
 * */
pub struct DefineStream {
    memory: memory::Memory
}

impl DefineStream {
    pub fn write(&mut self, instruction: Instruction) {
        /*
         * TODO 当前直接写入到内存中
         * */
        self.memory.write(instruction);
    }

    pub fn read(&mut self, addr: &FunctionAddrValue) -> DefineBlock {
        let block = DefineBlock{
            stream: self,
            pos: addr.start_pos_ref().clone(),
            length: addr.length_ref().clone()
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
                Some(RefPtr::from_ref::<Instruction>(v))
            },
            None => {
                None
            }
        }
    }
}

mod memory;

