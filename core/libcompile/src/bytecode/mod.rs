use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{FunctionDefine};
use libtypecontrol::function::FunctionControl;
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::instruction::Instruction;
use libresult::*;
use crate::compile::{ConstContext, CallFunctionContext
    , Compile, Compiler};

pub trait Writer {
    fn write(&mut self, instruction: Instruction) {
    }
}

pub struct Bytecode<F: Writer> {
    writer: F
}

impl<F: Writer> Compile for Bytecode<F> {
    fn const_number(&mut self, context: ConstContext) {
        match context.data {
            PrimevalData::Uint8(v) => {
                let instruction = Instruction::LoadUint8Const(v.expect("should not happend").to_std());
                self.writer.write(instruction);
            },
            PrimevalData::Uint16(v) => {
                let instruction = Instruction::LoadUint16Const(v.expect("should not happend").to_std());
                self.writer.write(instruction);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        // let instruction = Instruction::CallFunction(&context.func.func_define);
        match &context.func.func_define {
            FunctionDefine::Optcode(def) => {
                let instruction = Instruction::CallPrimevalFunction(def.optcode.clone());
                self.writer.write(instruction);
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl<F: Writer> Bytecode<F> {
    pub fn new(writer: F) -> Self {
        Self {
            writer: writer
        }
    }
}

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

    struct TestWriter {
    }

    impl Writer for TestWriter {
    }

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
                Bytecode{
                    writer: TestWriter{}
                }
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}