use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::{Function};
use libtypecontrol::function::FunctionControl;
use libtype::primeval::{PrimevalType, PrimevalData};
use libresult::*;

#[derive(Debug)]
pub struct ConstContext {
    pub typ: PrimevalType,
    pub data: PrimevalData
}

#[derive(Debug)]
pub struct CallFunctionContext<'a> {
    pub func: &'a Function
}

pub trait Compile {
    fn const_number(&mut self, context: ConstContext) {
        println!("{:?}", context);
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        println!("{:?}", context);
    }
}

pub struct Compiler<F: Compile> {
    function_control: FunctionControl,
    value_buffer: value_buffer::ValueBuffer,
    module_stack: module_stack::ModuleStack,
    cb: F
}

impl<F: Compile> Grammar for Compiler<F> {
    fn const_number(&mut self, value: TokenValue) {
	self.const_number(value);
    }

    fn operator_plus(&mut self, value: TokenValue) -> DescResult {
        self.operator_plus(value)
    }
}

mod module_stack;
mod value_buffer;
mod aide;
mod context;
mod constant;
mod operator;

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

    struct TestComplie {
    }

    impl Compile for TestComplie {
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
            cb: Compiler{
                function_control: FunctionControl::new(),
                value_buffer: value_buffer::ValueBuffer::new(),
                module_stack: module_stack::ModuleStack::new(
                    Module::new(String::from("main"))),
                cb: TestComplie{}
            }
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
