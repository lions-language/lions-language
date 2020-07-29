use libtype::instruction::{
    Instruction, CallFunction};
use libcommon::ptr::RefPtr;
use libcommon::address::FunctionAddress;
use libtype::package::{PackageStr};
use libcompile::define_stream::DefineStream;
use std::collections::VecDeque;

/*
 * 链接定义
 *  1. 获取 正在被编译的 package 的 package_index 映射
 *  2. 读取 package_index 映射, 建立真实地址的映射
 * 注意:
 *  1. 自身的定义的起始地址是0(自身包的定义写在最前面), 也就是说第三方包的起始地址至少是自身包的长度
 * */

pub struct LinkDefine {
    define_stream: RefPtr,
    code_segment: VecDeque<Instruction>,
    addr: usize
}

impl LinkDefine {
    pub fn start(&mut self, instruction: &Instruction) {
        let mut index = 0;
        self.execute(instruction, true, &mut index);
    }

    fn call_itself_func(&mut self, call_context: &CallFunction, index: &mut usize) {
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
            self.execute(instruction.as_ref::<Instruction>(), false, index);
        }
    }

    fn execute(&mut self, instruction: &Instruction, is_first: bool, index: &mut usize) {
        match instruction {
            Instruction::CallFunction(value) => {
                let ps = value.package_str_ref();
                match ps {
                    PackageStr::Itself => {
                        /*
                         * 从 define_stream 中查找
                         * */
                        self.call_itself_func(&value, index);
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
            _ => {
            }
        }
        if !is_first {
            self.code_segment.push_back(instruction.clone());
            *index += 1;
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

    pub fn new(define_stream: RefPtr) -> Self {
        let length = define_stream.as_ref::<DefineStream>().length();
        Self {
            define_stream: define_stream,
            code_segment: VecDeque::with_capacity(length),
            addr: length
        }
    }
}
