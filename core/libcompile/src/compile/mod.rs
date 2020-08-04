use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::{Type, Data};
use libtype::function::{Function, CallFunctionParamAddr};
use libtypecontrol::function::FunctionControl;
use libtype::module::Module;
use libresult::*;
use libtype::{AddressKey, AddressValue};
use libtype::package::{PackageStr};
use libmacro::{FieldGet, FieldGetMove, NewWithAll};
use crate::address;
use crate::address::PackageIndex;
use crate::static_dispatch::{StaticVariantDispatch};
use scope::context::ScopeContext;

#[derive(Debug)]
pub struct StaticContext {
    pub package_str: PackageStr,
    pub addr: AddressValue,
    pub static_addr: AddressKey
}

#[derive(Debug, FieldGet, NewWithAll
    , FieldGetMove)]
pub struct LoadStackContext {
    addr: AddressValue,
    data: Data
}

#[derive(Debug)]
pub struct CallFunctionContext<'a> {
    pub package_str: PackageStr,
    pub func: &'a Function,
    pub param_addrs: Option<Vec<CallFunctionParamAddr>>,
    pub return_addr: AddressValue
}

#[derive(Debug, FieldGet)]
pub struct FunctionNamedStmtContext {
    name: String
}

pub enum CompileType {
    Runtime,
    Compile
}

trait TokenValueExpand {
    fn to_type(&self) -> Type;
    fn to_data(self) -> Data;
}

pub trait Compile {
    fn const_number(&mut self, context: StaticContext) {
        println!("{:?}", context);
    }

    fn const_string(&mut self, _context: StaticContext) {
        unimplemented!();
    }

    fn load_stack(&mut self, _context: LoadStackContext) {
        unimplemented!();
    }

    fn load_variant(&mut self, addr: &address::Address) {
        println!("{:?}", addr);
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        println!("{:?}", context);
    }

    fn function_named_stmt(&mut self, _context: FunctionNamedStmtContext) {
    }
    
    fn function_define_start(&mut self) {
        unimplemented!();
    }

    fn function_define_end(&mut self) -> Function {
        unimplemented!();
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

pub struct Compiler<'a, F: Compile> {
    function_control: FunctionControl,
    module_stack: module_stack::ModuleStack,
    scope_context: ScopeContext,
    input_context: InputContext,
    package_index: &'a mut PackageIndex,
    static_variant_dispatch: &'a mut StaticVariantDispatch<'a>,
    package_str: &'a str,
    cb: F
}

impl<'a, F: Compile> Grammar for Compiler<'a, F> {
    fn const_number(&mut self, value: TokenValue) {
	self.const_number(value);
    }

    fn const_string(&mut self, value: TokenValue) {
        self.handle_const_string(value);
    }

    fn operator_plus(&mut self, value: TokenValue) -> DescResult {
        self.operator_plus(value)
    }

    fn end(&mut self) -> DescResult {
        self.handle_end()
    }

    fn function_named_stmt(&mut self, value: TokenValue) {
        self.handle_function_named_stmt(value);
    }

    fn function_define_start(&mut self, _value: TokenValue) {
        self.handle_function_define_start();
    }

    fn function_define_param(&mut self, name_token: TokenValue, type_token: TokenValue) {
        self.handle_function_define_param(name_token, type_token);
    }

    fn function_define_end(&mut self, _value: TokenValue) {
        self.handle_function_define_end();
    }

    fn call_function(&mut self, param_len: usize, names: Vec<TokenValue>) -> DescResult {
        self.handle_call_function(param_len, names)
    }
}

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn new(module: Module, cb: F, input_context: InputContext
        , package_index: &'a mut PackageIndex
        , static_variant_dispatch: &'a mut StaticVariantDispatch<'a>
        , package_str: &'a str) -> Self {
        Self {
            function_control: FunctionControl::new(),
            module_stack: module_stack::ModuleStack::new(module),
            scope_context: ScopeContext::new(),
            input_context: input_context,
            package_index: package_index,
            static_variant_dispatch: static_variant_dispatch,
            package_str: package_str,
            cb: cb
        }
    }
}

mod module_stack;
mod value_buffer;
mod ref_count;
mod address_dispatch;
mod compile_status_dispatch;
pub mod define;
mod aide;
mod context;
mod constant;
mod operator;
mod end;
mod function;
mod scope;
mod funccall;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use crate::static_stream::StaticStream;
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
        let mut package_index = PackageIndex::new();
        let mut static_stream = StaticStream::new();
        let mut static_variant_dispatch = StaticVariantDispatch::new(&mut static_stream);
        let package_str = String::from("test");
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(Module::new(String::from("main"))
                    , TestComplie{}, InputContext::new(InputAttribute::new(
                            FileType::Main))
                    , &mut package_index
                    , &mut static_variant_dispatch
                    , &package_str)
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
