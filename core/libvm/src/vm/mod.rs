use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{FunctionDefine};
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::instruction::{Instruction, AddressValue};
use libcompile::compile::{ConstContext, CallFunctionContext
    , Compile, Compiler};
use libcompile::bytecode::{Bytecode, Writer};
use libcommon::optcode;
use libcompile::address::AddressKey;
use crate::memory::{stack, Rand};
use libcommon::ptr::RefPtr;
use crate::data::Data;

struct MemoryContext {
    static_stack: stack::RandStack,
    thread_stack: stack::RandStack,
    static_addr_mapping: addr_mapping::AddressMapping,
    thread_addr_mapping: addr_mapping::AddressMapping
}

impl MemoryContext {
    fn new() -> Self {
        Self {
            static_stack: stack::RandStack::new(),
            thread_stack: stack::RandStack::new(),
            static_addr_mapping: addr_mapping::AddressMapping::new(),
            thread_addr_mapping: addr_mapping::AddressMapping::new(),
        }
    }
}

pub struct VirtualMachine {
    calc_stack: stack::TopStack<AddressValue>,
    memory_context: MemoryContext
}

impl Writer for VirtualMachine {
    fn write(&mut self, instruction: Instruction) {
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
            Instruction::CallPrimevalFunction(v) => {
                self.call_primeval_function(v);
            },
            Instruction::LoadVariant(v) => {
                self.load_variant(v);
            },
            _ => {
                unimplemented!("{:?}", &instruction);
            }
        }
    }
}

trait AddressControl {
    fn get_data_unchecked(&self, memory_context: &MemoryContext)
        -> RefPtr;
    fn alloc_and_write_data(&self, data: Data
        , memory_context: &mut MemoryContext);
}

impl AddressControl for AddressValue {
    /*
     * 获取编译期地址对应的数据
     * */
    fn get_data_unchecked(&self, memory_context: &MemoryContext)
        -> RefPtr {
        match self {
            AddressValue::Static(a) => {
                /*
                 * 处理静态区
                 *  1. 通过编译器的地址找到运行时映射的地址
                 *  2. 通过运行时地址, 找到实际的数据
                 *  3. 因为避开 rust 编译器的借用检查(这里我们可以保证数据的准确性)
                 *      需要将引用转换为指针
                 * */
                let run_addr =
                memory_context.static_addr_mapping.get_unwrap(
                    &AddressKey::new_without_module(*a));
                let data = memory_context.static_stack.get_unwrap(run_addr);
                RefPtr::from_ref::<Data>(data)
            },
            AddressValue::Stack(a) => {
                /*
                 * 处理栈区
                 * */
                 let run_addr =
                 memory_context.thread_addr_mapping.get_unwrap(
                    &AddressKey::new_without_module(*a));
                 let data = memory_context.thread_stack.get_unwrap(run_addr);
                 RefPtr::from_ref::<Data>(data)
            },
            _ => {
                unimplemented!();
            }
        }
    }

    /*
     * 根据编译期的指示, 创建运行时内存, 并将数据写入到相应的运行时内存
     * */
    fn alloc_and_write_data(&self, data: Data
        , memory_context: &mut MemoryContext) {
        match self {
            AddressValue::Static(a) => {
                /*
                 * 1. 在静态区分配一个新的内存
                 * 2. 将返回的地址和编译期的地址进行绑定
                 * */
                let run_addr = memory_context.static_stack.alloc(data);
                memory_context.static_addr_mapping.bind(
                    AddressKey::new_without_module(*a)
                    , run_addr);
            },
            AddressValue::Stack(a) => {
                let run_addr = memory_context.thread_stack.alloc(data);
                memory_context.thread_addr_mapping.bind(
                    AddressKey::new_without_module(*a)
                    , run_addr);
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl VirtualMachine {
    fn memory_mut(&mut self, addr: &AddressValue) -> &mut dyn Rand {
        match addr {
            AddressValue::Static(_) => {
                &mut self.memory_context.static_stack
            },
            AddressValue::Stack(_) => {
                &mut self.memory_context.thread_stack
            },
            _ => {
                panic!("should not happend");
            }
        }
    }

    pub fn new() -> Self {
        Self {
            calc_stack: stack::TopStack::new(),
            memory_context: MemoryContext::new()
        }
    }
}

mod load_const;
mod load_variant;
mod primeval_func_call;
mod addr_mapping;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use super::*;

    use std::fs;
    use std::io::Read;

    #[test]
    fn grammar_parser_test() {
        let file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(_err) => {
                panic!("read file error");
            }
        };
        let lexical_parser = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let f_ref = f.by_ref();
            match f_ref.take(1).read_to_end(&mut v) {
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
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(
                Module::new(String::from("main")),
                Bytecode::new(
                    VirtualMachine::new()
                )
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
