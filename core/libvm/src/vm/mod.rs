use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{FunctionDefine};
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::instruction::Instruction;
use libcompile::compile::{ConstContext, CallFunctionContext
    , Compile, Compiler};
use libcompile::bytecode::{Bytecode, Writer};
use libcommon::optcode;
use crate::memory::thread_stack;

pub struct VirtualMachine {
    thread_stack: thread_stack::Stack
}

impl Writer for VirtualMachine {
    fn write(&mut self, instruction: Instruction) {
        match instruction {
            Instruction::LoadUint8Const(d) => {
                self.load_const_uint8(d);
            },
            Instruction::LoadUint16Const(d) => {
                self.load_const_uint16(d);
            },
            Instruction::CallPrimevalFunction(d) => {
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

mod load_const;

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
                    VirtualMachine{
                        thread_stack: thread_stack::Stack::new()
                    }
                )
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
