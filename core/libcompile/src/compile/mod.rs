use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::{PackageType, PackageTypeValue};
use libtype::function::{Function};
use libtypecontrol::function::FunctionControl;
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::module::Module;
use libtype::function::{FindFunctionContext};
use libresult::*;
use libtype::{AddressKey, AddressValue};
use libcommon::ptr::{RefPtr};
use libmacro::{FieldGet};
use crate::address;
use crate::status::CompileStatus;

#[derive(Debug)]
pub struct ConstContext {
    pub typ: PrimevalType,
    pub data: PrimevalData,
    pub addr: AddressKey
}

#[derive(Debug)]
pub struct CallFunctionContext<'a> {
    pub func: &'a Function,
    pub return_addr: AddressValue
}

pub enum CompileType {
    Runtime,
    Compile
}

pub trait Compile {
    fn const_number(&mut self, context: ConstContext) {
        println!("{:?}", context);
    }

    fn load_variant(&mut self, addr: &address::Address) {
        println!("{:?}", addr);
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        println!("{:?}", context);
    }

    fn update_compile_status(&mut self, compile_status: CompileStatus) {
    }
}

pub enum FileType {
    Main
}

#[derive(FieldGet)]
pub struct InputAttribute {
    file_typ: FileType
}


impl InputAttribute {
    pub fn new(file_typ: FileType) -> Self {
        Self {
            file_typ: file_typ
        }
    }
}

#[derive(FieldGet)]
pub struct InputContext {
    attr: InputAttribute
}

impl InputContext {
    pub fn new(attr: InputAttribute) -> Self {
        Self {
            attr: attr
        }
    }
}

pub struct Compiler<F: Compile> {
    function_control: FunctionControl,
    value_buffer: value_buffer::ValueBuffer,
    module_stack: module_stack::ModuleStack,
    address_dispatch: address_dispatch::AddressDispatch,
    static_addr_dispatch: address_dispatch::AddressDispatch,
    ref_counter: ref_count::RefCounter,
    compile_status_dispatch: compile_status_dispatch::CompileStatusDispatch,
    input_context: InputContext,
    cb: F
}

impl<F: Compile> Grammar for Compiler<F> {
    fn const_number(&mut self, value: TokenValue) {
	self.const_number(value);
    }

    fn operator_plus(&mut self, value: TokenValue) -> DescResult {
        self.operator_plus(value)
    }

    fn end(&mut self) {
        if let FileType::Main = self.input_context.attr_ref().file_typ_ref() {
            /*
             * 查找 main 函数的声明
             * */
            self.function_control.find_function(&FindFunctionContext{
                typ: None,
                package_typ: Some(&PackageType::new(PackageTypeValue::Crate)),
                func_str: "main",
                module_str: self.module_stack.current().name_ref()
            }, &None);
        };
    }
}

impl<F: Compile> Compiler<F> {
    fn enter_function_define(&mut self, ptr: RefPtr) {
        self.compile_status_dispatch.enter(ptr);
        self.cb.update_compile_status(self.compile_status_dispatch.status());
    }

    fn leave_function_define(&mut self) {
        self.compile_status_dispatch.leave();
        self.cb.update_compile_status(self.compile_status_dispatch.status());
    }

    pub fn new(module: Module, cb: F, input_context: InputContext) -> Self {
        Self {
            function_control: FunctionControl::new(),
            value_buffer: value_buffer::ValueBuffer::new(),
            module_stack: module_stack::ModuleStack::new(module),
            address_dispatch: address_dispatch::AddressDispatch::new(0),
            static_addr_dispatch: address_dispatch::AddressDispatch::new(0),
            ref_counter: ref_count::RefCounter::new(),
            compile_status_dispatch: compile_status_dispatch::CompileStatusDispatch::new(),
            input_context: input_context,
            cb: cb
        }
    }
}

mod module_stack;
mod value_buffer;
mod ref_count;
mod address_dispatch;
mod compile_status_dispatch;
mod static_dispatch;
pub mod define;
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
    #[ignore]
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
            cb: Compiler::new(Module::new(String::from("main"))
                    , TestComplie{}, InputContext::new(InputAttribute::new(
                            FileType::Main)))
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
