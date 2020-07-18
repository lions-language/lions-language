use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{FunctionDefine};
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::instruction::{Instruction, AddressValue};
use libcompile::compile::{ConstContext, CallFunctionContext
    , Compile, Compiler};
use libcompile::bytecode::{Bytecode, Writer};
use libcommon::optcode;
use crate::memory::{stack, Memory};

pub struct VirtualMachine {
    static_stack: stack::Stack,
    thread_stack: stack::Stack,
    addr_mapping: addr_mapping::AddressMapping
}

impl Writer for VirtualMachine {
    fn write(&mut self, instruction: Instruction) {
        println!("{:?}", &instruction);
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

impl VirtualMachine {
    fn memory_mut(&mut self, addr: &AddressValue) -> &mut dyn Memory {
        match addr {
            AddressValue::Static(_) => {
                &mut self.static_stack
            },
            AddressValue::Stack(_) => {
                &mut self.thread_stack
            },
            _ => {
                panic!("should not happend");
            }
        }
    }

    pub fn new() -> Self {
        Self {
            static_stack: stack::Stack::new(),
            thread_stack: stack::Stack::new(),
            addr_mapping: addr_mapping::AddressMapping::new()
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
