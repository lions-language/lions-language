use libtype::instruction::{
    Instruction, CallFunction
    , CallSelfFunction, JumpType};
use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddress, FunctionAddrValue};
use libtype::package::{PackageStr};
use libcompile::define_stream::{DefineStream};
use std::collections::{VecDeque, HashMap};
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
    /*
     * key: define_stream 中 define_item 的索引
     * value: 在代码块段的映射, 也就是 FunctionAddrValue
     * 作用:
     *  防止重复写入
     * */
    define_mapping: HashMap<usize, FunctionAddrValue>,
    /*
     * 每次向 define_mapping 插入的时候, 需要向该数组中追加一个元素
     * 最后按照该数组中的值依次 拷贝 DefineStream 中对应的 DefineItem
     * */
    define_seque: Vec<usize>,
    index: usize,
    code_segment: VecDeque<Instruction>,
    /*
     * 第三方包的起始地址, 当前包的地址不用改变
     * */
    other_addr: usize
}

impl LinkDefine {
    /*
    pub fn start(&mut self, instruction: &mut Instruction) {
        self.link_static.start();
        self.execute(instruction, true);
    }
    */
    pub fn start(&mut self, instruction: &mut Instruction) {
        self.link_static.start();
        /*
         * 将第一句指令写入到代码段 (main入口)
         * */
        self.code_segment.push_back(instruction.clone());
        self.index += 1;
        self.execute(instruction, true);
        /*
         * 修改地址完成 => 将 define_stream 中的指令拷贝到代码段中
         * */
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
        for index in self.define_seque.iter() {
            self.code_segment.append(ds.get_all_ins_mut_unchecked(index.clone()).get_mut());
        }
        /*
         * print
         * */
        for (i, item) in self.code_segment.iter().enumerate() {
            println!("{}: {:?}", i, item);
        }
    }

    pub fn link_static(&mut self) -> &mut LinkStatic {
        &mut self.link_static
    }

    pub fn call_local_func(&mut self, call_context: &mut CallFunction) {
        let src_addr = match call_context.define_addr_mut() {
            FunctionAddress::Define(v) => {
                v
            },
            _ => {
                unimplemented!();
            }
        };
        let mut ds = self.define_stream.clone();
        let ds = ds.as_mut::<DefineStream>();
        let define_block = ds.read(src_addr, true);
        for mut instruction in define_block {
            self.execute(instruction.as_mut::<Instruction>(), false);
        }
        /*
         * 修改地址
         * */
        *src_addr = self.alloc_func_define_addr(src_addr);
    }

    fn call_self_func(&mut self, call_context: &mut CallSelfFunction) {
        let func_define_addr = match call_context.func_define_addr_mut() {
            FunctionAddress::Define(v) => {
                v
            },
            _ => {
                unimplemented!();
            }
        };
        let mut ds = self.define_stream.clone();
        let ds = ds.as_mut::<DefineStream>();
        let define_block = ds.read(func_define_addr, true);
        let define_item_ptr = define_block.item_clone();
        let define_item = define_item_ptr.get();
        let define_item_data = define_item.data_clone();
        let item_data = define_item_data.pop::<libcompile::define::FunctionDefineItemData>();
        *func_define_addr = self.alloc_func_define_addr(func_define_addr);
        // println!("{}", item_data.after_param_index_ref());
        *func_define_addr.index_mut() += item_data.after_param_index_clone();
        define_item_data.push(item_data);
        define_item_ptr.restore(define_item);
        // *src_addr = self.alloc_func_define_addr(src_addr);
    }

    fn execute(&mut self, instruction: &mut Instruction, is_first: bool) {
        // println!("{:?}", instruction);
        match instruction {
            Instruction::CallFunction(value) => {
                let ps = value.package_str_ref();
                match ps {
                    PackageStr::Itself => {
                        /*
                         * 从 define_stream 中查找
                         * */
                        self.call_local_func(value);
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
            Instruction::CallSelfFunction(value) => {
                self.call_self_func(value);
                println!("{:?}", value);
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
    }

    fn alloc_func_define_addr(&mut self, src_addr: &FunctionAddrValue)
        -> FunctionAddrValue {
        // let src_index = src_addr.index_clone();
        // let src_length = src_addr.length_clone();
        match self.define_mapping.get(src_addr.index_ref()) {
            Some(addr) => {
                /*
                 * 存在 => 直接返回地址
                 * */
                addr.clone()
            },
            None => {
                /*
                 * 不存在 => 新建并插入
                 * */
                let addr = FunctionAddrValue::new(
                    self.index.clone(), src_addr.length_clone());
                self.define_mapping.insert(
                    src_addr.index_clone(), addr.clone());
                self.define_seque.push(src_addr.index_clone());
                self.index += src_addr.length_clone();
                addr
            }
        }
    }

    /*
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
        let define_block = ds.read(address_value, true);
        for instruction in define_block {
            self.execute(instruction.as_ref::<Instruction>(), false);
        }
    }

    fn execute(&mut self, instruction: &Instruction, is_first: bool) {
        // println!("{:?}", instruction);
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
    */

    pub fn read(&self, addr: &FunctionAddrValue) -> LinkDefineBlock {
        println!("read: {:?}", addr);
        let pos = addr.index_clone();
        let length = addr.length_clone() + pos;
        LinkDefineBlock {
            link_define: self,
            pos: pos,
            length: length
        }
    }

    pub fn new(define_stream: RefPtr
        , static_stream: RefPtr) -> Self {
        let length = define_stream.as_ref::<DefineStream>().length();
        Self {
            define_stream: define_stream,
            link_static: LinkStatic::new(static_stream),
            define_mapping: HashMap::new(),
            define_seque: Vec::new(),
            index: 0,
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

impl<'a> LinkDefineBlock<'a> {
    fn update_pos(&mut self, ins: &Instruction) -> Option<Instruction> {
        match ins {
            Instruction::Jump(jp) => {
                // println!("{}", self.pos);
                match jp.typ_ref() {
                    JumpType::Backward => {
                        // println!("{}, {:?}", self.pos, jp);
                        self.pos += jp.index_clone();
                        // println!("index: {}", jp.index_ref());
                        // self.pos += 1;
                        // println!("{:?}", self.pos);
                    },
                    JumpType::Forward => {
                        self.pos -= jp.index_clone();
                    }
                }
                if self.pos == self.length {
                    return None;
                }
                match self.link_define.code_segment.get(self.pos) {
                    Some(v) => {
                        /*
                        println!("{}", self.pos);
                        println!("before: {:?}, after: {:?}"
                            , ins, v);
                        */
                        return Some(v.clone());
                    },
                    None => {
                        return None;
                    }
                }
            },
            _ => {
                self.pos += 1;
                return Some(ins.clone());
            }
        }
    }
}

impl<'a> Iterator for LinkDefineBlock<'a> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.length {
            return None;
        }
        match self.link_define.code_segment.get(self.pos) {
            Some(v) => {
                // self.pos += 1;
                // println!("{:?}", v);
                match self.update_pos(v) {
                    Some(ins) => {
                        // println!("{:?}", ins);
                        // println!("{}, {:?}", self.pos, ins);
                        Some(ins)
                    },
                    None => {
                        None
                    }
                }
                // Some(v.clone())
            },
            None => {
                None
            }
        }
    }
}
