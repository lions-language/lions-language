use libtype::instruction::{
    Instruction, CallFunction
    , BlockDefine, Jump
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

#[derive(PartialEq, Eq, Hash, Clone)]
struct DefineUnique {
    index: usize,
    define_stream: RefPtr
}

impl DefineUnique {
    fn new(index: usize, define_stream: RefPtr) -> Self {
        Self {
            index: index,
            define_stream: define_stream
        }
    }
}

pub struct LinkDefine {
    define_stream: RefPtr,
    link_static: LinkStatic,
    /*
     * key: define_stream 中 define_item 的索引
     * value: 在代码块段的映射, 也就是 FunctionAddrValue
     * 作用:
     *  防止重复写入
     * */
    define_mapping: HashMap<DefineUnique, FunctionAddrValue>,
    /*
     * 每次向 define_mapping 插入的时候, 需要向该数组中追加一个元素
     * 最后按照该数组中的值依次 拷贝 DefineStream 中对应的 DefineItem
     * */
    define_seque: Vec<DefineUnique>,
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
        self.execute(instruction, true, None);
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
        /*
        let mut ds = self.define_stream.clone();
        let ds = ds.as_mut::<DefineStream>();
        */
        for du in self.define_seque.iter() {
            let mut ds = du.define_stream.clone();
            let ds = ds.as_mut::<DefineStream>();
            self.code_segment.append(ds.get_all_ins_mut_unchecked(du.index.clone()).get_mut());
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

    pub fn call_local_func(&mut self, call_context: &mut CallFunction
        , define_stream: RefPtr) {
        let src_addr = match call_context.define_addr_mut() {
            FunctionAddress::Define(v) => {
                v
            },
            _ => {
                unimplemented!();
            }
        };
        /*
         * 如果定义过 => 直接将定义过的地址拿来
         * */
        if let Some(addr) = self.is_defined(src_addr, define_stream.clone()) {
            *src_addr = addr.clone();
            return;
        };
        /*
         * 修改地址
         * */
        let src_addr_clone = src_addr.clone();
        *src_addr = self.alloc_func_define_addr(src_addr, define_stream);
        let mut ds = self.define_stream.clone();
        let ds = ds.as_mut::<DefineStream>();
        let define_block = ds.read(&src_addr_clone, true);
        for mut instruction in define_block {
            self.execute(instruction.as_mut::<Instruction>(), false, None);
        }
    }

    pub fn call_package_func(&mut self, call_context: &mut CallFunction
        , define_stream: RefPtr, ps: &PackageStr) {
        let src_addr = match call_context.define_addr_mut() {
            FunctionAddress::Define(v) => {
                v
            },
            _ => {
                unimplemented!();
            }
        };
        /*
         * 如果定义过 => 直接将定义过的地址拿来
         * */
        if let Some(addr) = self.is_defined(src_addr, define_stream.clone()) {
            *src_addr = addr.clone();
            return;
        };
        /*
         * 修改地址
         * */
        let src_addr_clone = src_addr.clone();
        *src_addr = self.alloc_func_define_addr(src_addr, define_stream.clone());
        let mut ds = define_stream;
        let ds = ds.as_mut::<DefineStream>();
        let define_block = ds.read(&src_addr_clone, true);
        for mut instruction in define_block {
            self.execute(instruction.as_mut::<Instruction>(), false, Some(ps));
        }
    }

    pub fn process_block_define(&mut self, block_define: &mut BlockDefine
        , define_stream: RefPtr) {
        let src_addr = block_define.addr_mut();
        /*
         * 如果定义过 => 直接将定义过的地址拿来
         * */
        if let Some(addr) = self.is_defined(src_addr, define_stream.clone()) {
            *src_addr = addr.clone();
            return;
        };
        /*
         * 修改地址
         * */
        let src_addr_clone = src_addr.clone();
        *src_addr = self.alloc_func_define_addr(src_addr, define_stream);
        let mut ds = self.define_stream.clone();
        let ds = ds.as_mut::<DefineStream>();
        let define_block = ds.read(&src_addr_clone, true);
        for mut instruction in define_block {
            self.execute(instruction.as_mut::<Instruction>(), false, None);
        }
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
        // *src_addr = self.alloc_func_define_addr(src_addr);
    }

    fn execute(&mut self, instruction: &mut Instruction, is_first: bool
        , package_str: Option<&PackageStr>) {
        // println!("{:?}", instruction);
        match instruction {
            Instruction::CallFunction(value) => {
                // let ps = value.package_str_ref();
                let ps = match package_str {
                    Some(ps) => ps.clone(),
                    None => {
                        value.package_str_clone()
                    }
                };
                match &ps {
                    PackageStr::Itself => {
                        /*
                         * 从 define_stream 中查找
                         * */
                        self.call_local_func(value, self.define_stream.clone());
                    },
                    PackageStr::Third(pbp) => {
                        /*
                         * 1. 遇到新的包, 需要获取包编译后的函数位置, 然后链接到这里来
                         * 2. 使用链接后的地址, 重写这里的 call 地址
                         * */
                        self.call_package_func(value, pbp.define_stream.clone(), &ps);
                    },
                    _ => {
                        panic!("should not happend");
                    }
                }
            },
            Instruction::IfStmt(value) => {
                self.process_block_define(value.true_handle_mut().define_mut()
                    , self.define_stream.clone());
            },
            Instruction::WhileStmt(value) => {
                self.process_block_define(value.true_handle_mut().define_mut()
                    , self.define_stream.clone());
            },
            Instruction::ExecuteBlock(value) => {
                self.process_block_define(value
                    , self.define_stream.clone());
            },
            Instruction::CallSelfFunction(value) => {
                self.call_self_func(value);
            },
            Instruction::ReadStaticVariant(_) => {
                /*
                 * 从 static_stream 中查找
                 * */
                self.link_static.process(instruction, package_str);
            },
            _ => {
            }
        }
    }

    fn is_defined(&mut self, src_addr: &FunctionAddrValue, define_stream: RefPtr)
        -> Option<&FunctionAddrValue> {
        self.define_mapping.get(&DefineUnique{
            index: src_addr.index_clone(),
            define_stream: define_stream
        })
        // self.define_mapping.get(src_addr.index_ref())
    }

    fn alloc_func_define_addr(&mut self, src_addr: &FunctionAddrValue
        , define_stream: RefPtr)
        -> FunctionAddrValue {
        // let src_index = src_addr.index_clone();
        // let src_length = src_addr.length_clone();
        // match self.define_mapping.get(src_addr.index_ref()) {
        let define_unique = DefineUnique{
            index: src_addr.index_clone(),
            define_stream: define_stream.clone()
        };
        match self.define_mapping.get(&define_unique) {
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
                /*
                */
                let ds = define_stream.as_ref::<DefineStream>();
                let item_object = ds.item_clone_unchecked(src_addr);
                let item = item_object.get();
                let addr = FunctionAddrValue::new_valid(
                    self.index.clone(), item.length());
                item_object.restore(item);
                /*
                self.define_mapping.insert(
                    src_addr.index_clone(), addr.clone());
                self.define_seque.push(src_addr.index_clone());
                */
                self.define_mapping.insert(define_unique.clone(), addr.clone());
                self.define_seque.push(define_unique);
                self.index += addr.length_clone();
                addr
            }
        }
    }

    pub fn read(&self, addr: &FunctionAddrValue) -> LinkDefineBlock {
        // println!("read: {:?}", addr);
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
    pub fn current_pos_clone(&self) -> usize {
        self.pos.clone()
    }

    pub fn block_length_clone(&self) -> usize {
        self.length.clone()
    }

    /*
    pub fn current_pos_ref(&self) -> &usize {
        &self.pos
    }

    pub fn block_length_ref(&self) -> &usize {
        &self.length
    }
    */

    pub fn get_next(&mut self) -> Option<&Instruction> {
        if self.pos == self.length {
            return None;
        }
        match self.link_define.code_segment.get(self.pos) {
            Some(v) => {
                /*
                match self.update_pos_ref(v) {
                    Some(ins) => {
                        // println!("{:?}", ins);
                        // println!("{}, {:?}", self.pos, ins);
                        Some(ins)
                    },
                    None => {
                        None
                    }
                }
                */
                self.pos += 1;
                Some(v)
            },
            None => {
                None
            }
        }
    }

    pub fn update_by_jump(&mut self, jump: &Jump) {
        match jump.typ_ref() {
            JumpType::Backward => {
                self.pos += jump.index_clone();
            },
            JumpType::Forward => {
                self.pos -= jump.index_clone();
            }
        }
    }

    fn update_pos_ref<'b>(&'b mut self, ins: &'b Instruction) -> Option<&'b Instruction> {
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
                        return Some(v);
                    },
                    None => {
                        return None;
                    }
                }
            },
            _ => {
                self.pos += 1;
                return Some(ins);
            }
        }
    }

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
                /*
                match self.update_pos(v) {
                    Some(ins) => {
                        Some(ins)
                    },
                    None => {
                        None
                    }
                }
                */
                self.pos += 1;
                Some(v.clone())
            },
            None => {
                None
            }
        }
    }
}
