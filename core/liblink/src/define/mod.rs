use libtype::instruction::{
    Instruction, CallFunction};
use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libtype::package::{PackageStr};
use libcompile::define_stream::{DefineStream};
use std::collections::VecDeque;
use crate::statics::LinkStatic;

/*
 * 链接定义
 *  1. 获取 正在被编译的 package 的 package_index 映射
 *  2. 读取 package_index 映射, 建立真实地址的映射
 * 注意:
 *  1. 自身的定义的起始地址是0(自身包的定义写在最前面), 也就是说第三方包的起始地址至少是自身包的长度
 * */

pub struct LinkDefine {
    define_stream: RefPtr,
    link_static: LinkStatic,
    code_segment: VecDeque<Instruction>,
    /*
     * 第三方包的起始地址, 当前包的地址不用改变
     * */
    other_addr: usize
}

impl LinkDefine {
    pub fn start(&mut self, instruction: &Instruction) {
        self.link_static.start();
        self.execute(instruction, true);
    }

    pub fn link_static(&mut self) -> &mut LinkStatic {
        &mut self.link_static
    }

    pub fn call_itself_func(&mut self, call_context: &CallFunction) {
        /*
         * 语法点:
         * let mut ds = self.define_stream.clone();
         * let ds = ds.as_mut::<DefineStream>();
         * 不能变为一句:
         * let ds = self.define_stream.as_mut::<DefineStream>();
         * 如果这样, 将导致 这里的 self 和 后面的 self.execute 在同一个作用域下的两个可变引用
         * 也就是借用检查器会不通过
         * */
        let mut ds = self.define_stream.clone();
        let ds = ds.as_mut::<DefineStream>();
        let address_value = match call_context.define_addr_ref() {
            FunctionAddress::Define(v) => {
                v
            },
            _ => {
                unimplemented!();
            }
        };
        let define_block = ds.read(address_value);
        for instruction in define_block {
            self.execute(instruction.as_ref::<Instruction>(), false);
        }
    }

    fn execute(&mut self, instruction: &Instruction, is_first: bool) {
        match instruction {
            Instruction::CallFunction(value) => {
                let ps = value.package_str_ref();
                match ps {
                    PackageStr::Itself => {
                        /*
                         * 从 define_stream 中查找
                         * */
                        self.call_itself_func(&value);
                    },
                    PackageStr::Third(_) => {
                        /*
                         * 1. 遇到新的包, 需要获取包编译后的函数位置, 然后链接到这里来
                         * 2. 使用链接后的地址, 重写这里的 call 地址
                         * */
                        unimplemented!();
                    },
                    _ => {
                        panic!("should not happend");
                    }
                }
            },
            Instruction::ReadStaticVariant(_) => {
                /*
                 * 从 static_stream 中查找
                 * */
                self.link_static.process(instruction);
            },
            _ => {
            }
        }
        if !is_first {
            self.code_segment.push_back(instruction.clone());
            /*
            match self.code_segment.get_mut(*index) {
                Some(v) => {
                    *v = instruction.clone();
                },
                None => {
                    panic!("should not happend");
                }
            }
            *index += 1;
            */
        }
    }

    pub fn read(&self, addr: &FunctionAddrValue) -> LinkDefineBlock {
        LinkDefineBlock {
            link_define: self,
            pos: addr.start_pos_ref().clone(),
            length: addr.length_ref().clone()
        }
    }

    pub fn new(define_stream: RefPtr
        , static_stream: RefPtr) -> Self {
        let length = define_stream.as_ref::<DefineStream>().length();
        Self {
            define_stream: define_stream,
            link_static: LinkStatic::new(static_stream),
            code_segment: VecDeque::with_capacity(length),
            other_addr: length,
        }
    }
}

pub struct LinkDefineBlock<'a> {
    link_define: &'a LinkDefine,
    pos: usize,
    length: usize
}

impl<'a> Iterator for LinkDefineBlock<'a> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.length {
            return None;
        }
        match self.link_define.code_segment.get(self.pos) {
            Some(v) => {
                self.pos += 1;
                Some(v.clone())
            },
            None => {
                None
            }
        }
    }
}
