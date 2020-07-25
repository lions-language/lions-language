use libtype::function::{FunctionDefine};
use libtype::primeval::{PrimevalData};
use libtype::instruction::{Instruction, CallPrimevalFunction
    , VariantValue, Uint8Static
    , Uint16Static, Uint32Static};
use crate::compile::{ConstContext, CallFunctionContext
    , Compile};
use crate::address;
use define_stack::DefineStack;

pub trait Writer {
    fn write(&mut self, _: Instruction) {
    }
}

pub struct Bytecode<F: Writer> {
    writer: F,
    define_stack: DefineStack
}

impl<F: Writer> Compile for Bytecode<F> {
    fn const_number(&mut self, context: ConstContext) {
        match context.data {
            PrimevalData::Uint8(v) => {
                let instruction = Instruction::LoadUint8Const(Uint8Static{
                    addr: context.addr,
                    value: v.expect("should not happend").to_std()
                });
                self.write(instruction);
            },
            PrimevalData::Uint16(v) => {
                let instruction = Instruction::LoadUint16Const(Uint16Static{
                    addr: context.addr,
                    value: v.expect("should not happend").to_std()
                });
                self.write(instruction);
            },
            PrimevalData::Uint32(v) => {
                let instruction = Instruction::LoadUint32Const(Uint32Static{
                    addr: context.addr,
                    value: v.expect("should not happend").to_std()
                });
                self.write(instruction);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn load_variant(&mut self, addr: &address::Address) {
        self.write(Instruction::LoadVariant(VariantValue::new(
                    addr.addr_clone())));
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        match &context.func.func_define {
            FunctionDefine::Optcode(def) => {
                let instruction = Instruction::CallPrimevalFunction(
                    CallPrimevalFunction{
                        opt: def.optcode.clone(),
                        return_addr: context.return_addr
                    }
                    );
                self.write(instruction);
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl<F: Writer> Bytecode<F> {
    fn write(&mut self, instruction: Instruction) {
        self.define_stack.write(instruction);
    }

    pub fn new(writer: F) -> Self {
        Self {
            writer: writer,
            define_stack: DefineStack::new()
        }
    }
}

mod define_stack;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use crate::compile::{Compiler, InputContext, InputAttribute, FileType};
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
                Bytecode::new(TestWriter{}),
                InputContext::new(InputAttribute::new(FileType::Main))
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
