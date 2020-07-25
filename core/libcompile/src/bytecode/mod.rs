use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{FunctionDefine};
use libtypecontrol::function::FunctionControl;
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::instruction::{Instruction, CallPrimevalFunction
    , VariantValue, Uint8Static
    , Uint16Static, Uint32Static};
use libtype::{AddressValue};
use libcommon::ptr::{RefPtr};
use libresult::*;
use crate::compile::{ConstContext, CallFunctionContext
    , Compile, Compiler};
use crate::address;
use crate::status::{CompileStatus, CompileStatusType};
use crate::compile::define;

pub trait Writer {
    fn write(&mut self, instruction: Instruction) {
    }
}

pub struct Bytecode<F: Writer> {
    writer: F,
    compile_status: CompileStatus,
    define_function_dispatch: define::Dispatch
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
    
    fn update_compile_status(&mut self, compile_status: CompileStatus) {
        *(&mut self.compile_status) = compile_status;
    }
}

impl<F: Writer> Bytecode<F> {
    fn write(&mut self, instruction: Instruction) {
        /*
         * 如果状态是 Define, 调用 DefineFunctionDispatch 的 write 方法
         * 如果是 Call, 调用 self.writer.write
         * */
        match self.compile_status.status_mut() {
            CompileStatusType::FunctionDefine(ptr) => {
                ptr.as_mut::<define::Item>().write(instruction);
            },
            CompileStatusType::Call => {
                self.writer.write(instruction);
            }
        }
    }

    pub fn new(writer: F) -> Self {
        Self {
            writer: writer,
            compile_status: CompileStatus::default(),
            define_function_dispatch: define::Dispatch::new()
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
    use crate::compile::{InputContext, InputAttribute, FileType};
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
