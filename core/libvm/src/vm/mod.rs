use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{FunctionDefine};
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::{AddressValue, AddressType, AddressKey};
use libtype::instruction::{Instruction, Jump};
use libcompile::compile::{StaticContext, CallFunctionContext
    , Compile, Compiler};
use libcompile::bytecode::{Bytecode, Writer};
use libcompile::define_stream::{DefineStream};
use libcommon::optcode;
use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddrValue};
use liblink::define::LinkDefine;
use liblink::statics::LinkStatic;
use liblink::link::Link;
use libtype::Data;
use crate::memory::{stack, Rand};
use crate::vm::thread_context::context::ThreadContext;

struct MemoryContext {
    static_stack: stack::rand::RandStack<usize>,
    thread_stack: stack::rand::RandStack<Data>,
    static_addr_mapping: addr_mapping::AddressMapping,
    thread_addr_mapping: addr_mapping::AddressMapping
}

impl MemoryContext {
    fn new() -> Self {
        Self {
            static_stack: stack::rand::RandStack::new(),
            thread_stack: stack::rand::RandStack::new(),
            static_addr_mapping: addr_mapping::AddressMapping::new(),
            thread_addr_mapping: addr_mapping::AddressMapping::new(),
        }
    }
}

pub struct VirtualMachine {
    calc_stack: stack::TopStack<AddressValue>,
    // memory_context: MemoryContext,
    thread_context: ThreadContext,
    link_define: RefPtr,
    link_static: RefPtr,
}

#[derive(Debug)]
pub enum ConditionResult {
    True,
    False
}

#[derive(Debug)]
pub enum ExecuteResult {
    ReturnFunc,
    Jump(Jump),
    Normal
}

impl VirtualMachine {
    fn execute(&mut self, instruction: Instruction
        , current_pos: &usize, block_length: &usize) -> ExecuteResult {
        // println!("{:?}", &instruction);
        match instruction {
            Instruction::LoadUint8Const(v) => {
                self.load_const_uint8(v);
            },
            Instruction::LoadUint16Const(v) => {
                self.load_const_uint16(v);
            },
            Instruction::LoadUint32Const(v) => {
                self.load_const_uint32(v);
            },
            Instruction::LoadStringConst(v) => {
                self.load_const_string(v);
            },
            Instruction::LoadStack(v) => {
                self.load_stack(v);
            },
            Instruction::CallPrimevalFunction(v) => {
                self.call_primeval_function(v);
            },
            Instruction::LoadVariant(v) => {
                self.load_variant(v);
            },
            Instruction::CallFunction(v) => {
                self.call_function(v, current_pos, block_length);
            },
            Instruction::OwnershipMove(v) => {
                self.ownership_move(v);
            },
            Instruction::AddressBind(v) => {
                self.address_bind(v);
            },
            Instruction::RemoveOwnership(v) => {
                self.remove_ownership(v);
            },
            Instruction::ReturnStmt(v) => {
                return self.process_return_stmt(v);
            },
            Instruction::IfStmt(v) => {
                return self.process_if_stmt(v);
            },
            Instruction::ConditionStmt(v) => {
                return self.process_condition_stmt(v);
            },
            Instruction::WhileStmt(v) => {
                return self.process_while_stmt(v);
            },
            Instruction::LoopStmt(v) => {
                return self.process_loop_stmt(v);
            },
            Instruction::ReadStaticVariant(v) => {
                self.read_static_variant(v);
            },
            Instruction::AddRefParamAddr(v) => {
                self.add_ref_param_addr(v);
            },
            Instruction::DeleteData(v) => {
                self.delete_data(v);
            },
            Instruction::EnterScope => {
                self.thread_context.enter_thread_scope();
            },
            Instruction::LeaveScope => {
                self.thread_context.leave_thread_scope();
            },
            Instruction::ExecuteBlock(v) => {
                return self.process_execute_block(v);
            },
            _ => {
                unimplemented!("{:?}", &instruction);
            }
        }
        ExecuteResult::Normal
    }

    pub fn run(&mut self, entrance: Instruction) {
        // println!("{:?}", entrance);
        /*
         * main 函数被调用的时候, 编译期不会生成 enter scope 指令
         * 所以这里需要手动进入
         * */
        self.thread_context.enter_thread_scope();
        self.execute(entrance, &0, &0);
        self.thread_context.leave_thread_scope();
    }

    /*
    fn memory_mut(&mut self, addr: &AddressValue) -> &mut dyn Rand<> {
        match addr.typ_ref() {
            AddressType::Static => {
                &mut self.memory_context.static_stack
            },
            AddressType::Stack => {
                &mut self.memory_context.thread_stack
            },
            _ => {
                panic!("should not happend");
            }
        }
    }
    */

    pub fn panic(&self, msg: &str) {
        println!("{}", msg);
        std::process::exit(0);
    }

    pub fn new(link_define: RefPtr
        , link_static: RefPtr) -> Self {
        Self {
            calc_stack: stack::TopStack::new(),
            // memory_context: MemoryContext::new(),
            thread_context: ThreadContext::new_with_first(),
            link_define: link_define,
            link_static: link_static
        }
    }
}

trait AddressControl {
    fn get_data_unchecked(&self, memory_context: &MemoryContext
        , link_static: &RefPtr)
        -> RefPtr;
    fn alloc_and_write_data(&self, data: Data
        , memory_context: &mut MemoryContext);
    fn alloc_and_write_static(&self, static_addr: usize
        , memory_context: &mut MemoryContext);
}

/*
impl AddressControl for AddressValue {
    /*
     * 获取编译期地址对应的数据
     * */
    fn get_data_unchecked(&self, memory_context: &MemoryContext
        , link_static: &RefPtr)
        -> RefPtr {
        match self.typ_ref() {
            AddressType::Static => {
                /*
                 * 处理静态区
                 *  1. 通过编译器的地址找到运行时映射的地址
                 *  2. 通过运行时地址, 找到实际的数据
                 *  3. 因为避开 rust 编译器的借用检查(这里我们可以保证数据的准确性)
                 *      需要将引用转换为指针
                 * */
                let data = link_static.as_ref::<LinkStatic>().read_uncheck(self.addr_ref());
                RefPtr::from_ref::<Data>(data)
            },
            AddressType::Stack => {
                /*
                 * 处理栈区
                 * */
                 let run_addr =
                 memory_context.thread_addr_mapping.get_unwrap(
                    self.addr_ref());
                 let data = memory_context.thread_stack.get_unwrap(run_addr);
                 RefPtr::from_ref::<Data>(data)
            },
            _ => {
                unimplemented!("{:?}", self.typ_ref());
            }
        }
    }

    /*
     * 根据编译期的指示, 创建运行时内存, 并将数据写入到相应的运行时内存
     * */
    fn alloc_and_write_data(&self, data: Data
        , memory_context: &mut MemoryContext) {
        match self.typ_ref() {
            AddressType::Stack => {
                let run_addr = memory_context.thread_stack.alloc(data);
                memory_context.thread_addr_mapping.bind(self.addr_clone()
                    , run_addr);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn alloc_and_write_static(&self, static_addr: usize
        , memory_context: &mut MemoryContext) {
        let run_addr = memory_context.static_stack.alloc(static_addr);
        memory_context.static_addr_mapping.bind(self.addr_clone()
            , run_addr);
    }
}
*/

mod load_const;
mod load_variant;
mod load_stack;
mod primeval_func_call;
mod addr_mapping;
mod func_call;
mod thread_context;
mod ownership;
mod address;
mod process_return;
mod process_if;
mod memory;
mod process_while;
mod process_condition;
mod process_loop;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use libtypecontrol::function::FunctionControl;
    use libstructtype::structure::{StructControl};
    use libinterfacetype::interface::{InterfaceControl};
    use libcompile::compile::{FileType, InputAttribute, InputContext, IoAttribute};
    use libcompile::module::{ModuleStack};
    use libcompile::define_dispatch::{FunctionDefineDispatch, BlockDefineDispatch};
    use libcompile::static_dispatch::{StaticVariantDispatch};
    use libcompile::static_stream::{StaticStream};
    use libcompile::address::PackageIndex;
    use libcompile::package::{Package, PackageContext, PackageControl};
    use libcompile::module::{ModuleMapping};
    use super::*;

    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    // use rust_parse::cmd::CCmd;

    #[test]
    fn virtual_machine_test() {
        /*
        let mut cmd_handler = CCmd::new();
        let path = cmd_handler.register_with_desc("-path", "main.lions", "main file path");
        cmd_handler.parse();
        let path = path.borrow();

        let file = String::from(&*path);
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(err) => {
                panic!("read file error, err: {}", err);
            }
        };
        */
        let file = String::from("tests/main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(err) => {
                panic!("read file error, err: {}", err);
            }
        };
        let path_buf = Path::new(&file).parent().expect("should not happend").to_path_buf();
        let io_attr = IoAttribute::new_with_all(1);
        let io_attr_clone = io_attr.clone();
        let lexical_parser = LexicalParser::new(file.clone()
            , || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let f_ref = f.by_ref();
            match f_ref.take(io_attr.read_once_max_clone() as u64).read_to_end(&mut v) {
                Ok(len) => {
                    if len == 0 {
                        return CallbackReturnStatus::End;
                    } else {
                        return CallbackReturnStatus::Continue(VecU8::from_vec_u8(v));
                    }
                },
                Err(_) => {
                    return CallbackReturnStatus::End;
                }
            }
        });
        let mut ds = DefineStream::new();
        let mut ss = StaticStream::new();
        let mut ds_ptr = RefPtr::from_ref::<DefineStream>(&ds);
        let mut ss_ptr = RefPtr::from_ref::<StaticStream>(&ss);
        let mut func_ds = ds_ptr.clone();
        let mut fdd = FunctionDefineDispatch::new(func_ds.as_mut::<DefineStream>());
        let mut bdd = BlockDefineDispatch::new(&mut ds);
        let mut static_variant_dispatch = StaticVariantDispatch::new(
            &mut ss);
        let mut package_str = String::from("test");
        let mut link = Link::new(ds_ptr
            , ss_ptr);
        let module = Module::new(String::from("main"), String::from("main"));
        let mut module_stack = ModuleStack::new();
        let mut function_control = FunctionControl::new();
        let mut struct_control = StructControl::new();
        let mut interface_control = InterfaceControl::new();
        let package = Package::<String>::new();
        let mut package_control = PackageControl::new();
        {
            /*
             * 添加 一个 package (假设 在编译第三方package)
             * */
            let this_package = Package::<PathBuf>::new();
            let this_package_control = PackageControl::new();
            let this_package_context = PackageContext::new(&this_package, &this_package_control);
            let this_package_name = "libnet";
            let this_config_item = libpackage::config::PackageConfigItem::<PathBuf>::new(
                true, 1, Path::new("tests/packages").join(this_package_name).to_path_buf(), None);
            let mut control = libpackage::control::Control::new();
            let this_package_buffer = control.single_compile::<PathBuf>(this_package_name
                , &this_config_item, &this_package_context);
            package_control.insert(this_package_name.to_string(), this_package_buffer);
        }
        let package_context = PackageContext::new(&package, &package_control);
        let mut module_mapping = ModuleMapping::new();
        let mut bytecode = Bytecode::new(
                &mut link
                , &mut fdd
                , &mut bdd
            );
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(
                &mut module_stack, Some(module)
                , &mut bytecode
                , InputContext::new(InputAttribute::new(FileType::Main)
                    , path_buf.clone(), path_buf.clone())
                , &mut static_variant_dispatch
                , &package_str, io_attr_clone
                , &mut function_control
                , &mut struct_control, &mut interface_control
                , &package_context
                , &mut module_mapping
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
        let entrance = link.call_main_instruction().clone();
        /*
         * 如果存在编译后的文件, 使用 LinkDefine 的读取功能 从文件中读取后实例化 LinkDefine
         * */
        let mut virtual_machine = VirtualMachine::new(
            RefPtr::from_ref::<LinkDefine>(link.link_define())
            , RefPtr::from_ref::<LinkStatic>(link.link_static()));
        virtual_machine.run(entrance);
    }
}
