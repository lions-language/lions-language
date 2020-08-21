use libcommon::ptr::RefPtr;
use libgrammar::grammar::{Grammar, CallFuncScopeContext
    , VarStmtContext, LoadVariantContext as GrammarLoadVariantContext
    , ConstNumberContext, ConstStringContext
    , CallFunctionContext as GrammarCallFunctionContext
    , FunctionDefineParamContext
    , FunctionDefineReturnContext
    , ReturnStmtContext as GrammarReturnStmtContext};
use libgrammar::token::{TokenValue};
use libtype::{Type, Data
    , TypeAttrubute};
use libtype::function::{Function, CallFunctionParamAddr
    , CallFunctionReturnData
    , FunctionParamDataItem
    , FunctionReturn};
use libtype::instruction::{Jump, RemoveOwnership};
use libtypecontrol::function::FunctionControl;
use libtype::module::Module;
use libresult::*;
use libtype::{AddressKey, AddressValue};
use libtype::package::{PackageStr};
use libmacro::{FieldGet, FieldGetClone, FieldGetMove, NewWithAll};
use crate::address;
use crate::address::PackageIndex;
use crate::static_dispatch::{StaticVariantDispatch};
use scope::context::ScopeContext;
use crate::define::DefineObject;

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

#[derive(Debug, FieldGet, NewWithAll
    , FieldGetMove)]
pub struct OwnershipMoveContext {
    pub dst_addr: AddressKey,
    pub src_addr: AddressValue
}

#[derive(Debug)]
pub struct CallFunctionContext<'a> {
    pub package_str: PackageStr,
    pub func: &'a Function,
    pub param_addrs: Option<Vec<CallFunctionParamAddr>>,
    pub call_param_len: usize,
    pub return_data: CallFunctionReturnData
}

#[derive(Debug, FieldGet)]
pub struct FunctionNamedStmtContext {
    name: String
}

#[derive(Debug, FieldGet)]
pub struct LoadVariantContext {
}

pub enum CompileType {
    Runtime,
    Compile
}

#[derive(Debug, FieldGet
    , FieldGetMove, FieldGetClone
    , NewWithAll)]
pub struct CompileContext {
    is_auto_call_totype: bool,
    expect_type: Type
}

impl Default for CompileContext {
    fn default() -> Self {
        Self {
            is_auto_call_totype: false,
            expect_type: Type::new_empty()
        }
    }
}

impl CompileContext {
    fn set(&mut self, context: CompileContext) {
        *self = context;
    }

    fn new(is_auto_call_totype: bool
        , expect_type: Type) -> Self {
        Self {
            is_auto_call_totype: is_auto_call_totype,
            expect_type: expect_type
        }
    }

    fn reset(&mut self) {
        *self = CompileContext::default()
    }
}

#[derive(Debug, FieldGet
    , FieldGetMove, FieldGetClone
    , NewWithAll)]
pub struct AddressBindContext {
    src_addr: AddressKey,
    dst_addr: AddressValue
}

#[derive(Debug, FieldGet
    , FieldGetMove, FieldGetClone
    , NewWithAll)]
pub struct ReturnStmtContext {
    scope: usize,
    addr_key: AddressKey
}

trait TokenValueExpand {
    fn to_type(&self) -> Type;
    fn to_data(self) -> Data;
}

trait AddressValueExpand {
    fn add_scope(&mut self, n: usize);
    fn clone_with_scope_plus(&self, n: usize) -> AddressValue;
    fn clone_with_scope_minus(&self, n: usize) -> AddressValue;
    fn addr_with_scope_minus(self, n: usize) -> AddressValue;
    fn addr_mut_with_scope_minus(&mut self, n: usize);
}

trait TypeTokenExpand {
    fn to_type(self) -> Type;
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

    fn load_variant(&mut self, _context: LoadVariantContext) {
        println!("load variant");
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        println!("{:?}", context);
    }

    fn function_named_stmt(&mut self, _context: FunctionNamedStmtContext) -> RefPtr {
        unimplemented!();
    }

    fn function_push_param_to_statement(&mut self
        , _item: FunctionParamDataItem) {
    }

    fn function_set_return_to_statement(&mut self
        , _item: FunctionReturn) {
    }
    
    fn function_define_start(&mut self) {
        println!("function define start");
    }

    fn function_define_end(&mut self) -> Function {
        unimplemented!();
    }

    fn ownership_move(&mut self, _context: OwnershipMoveContext) {
        unimplemented!();
    }

    fn address_bind(&mut self, _context: AddressBindContext) {
        unimplemented!();
    }

    fn return_stmt(&mut self, _context: ReturnStmtContext) {
        unimplemented!();
    }

    fn current_index(&self) -> usize {
        unimplemented!();
    }

    fn set_jump(&mut self, _: usize, _: Jump) {
        unimplemented!();
    }

    fn jump(&mut self, _context: Jump) -> usize {
        unimplemented!();
    }

    fn enter_scope(&mut self) {
        unimplemented!();
    }

    fn leave_scope(&mut self) {
        unimplemented!();
    }

    fn remove_ownership(&mut self, _context: RemoveOwnership) {
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
    compile_context: CompileContext,
    cb: F
}

impl<'a, F: Compile> Grammar for Compiler<'a, F> {
    fn const_number(&mut self, context: ConstNumberContext) {
	self.const_number(context);
    }

    fn const_string(&mut self, context: ConstStringContext) {
        self.handle_const_string(context);
    }

    fn load_variant(&mut self, context: GrammarLoadVariantContext) -> DescResult {
        self.handle_load_variant(context)
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

    fn function_define_param(&mut self, context: FunctionDefineParamContext) {
        self.handle_function_define_param(context);
    }

    fn function_define_return(&mut self, context: FunctionDefineReturnContext) {
        self.handle_function_define_return(context);
    }

    fn function_define_end(&mut self, _value: TokenValue) {
        self.handle_function_define_end();
    }

    fn call_function_prepare(&mut self, scope_context: CallFuncScopeContext
        , name: TokenValue, call_context: &mut GrammarCallFunctionContext) -> DescResult {
        self.handle_call_function_prepare(scope_context, name, call_context)
    }

    fn call_function_param_before_expr(&mut self, index: usize
        , call_context: &mut GrammarCallFunctionContext) {
        self.handle_call_function_param_before_expr(index, call_context);
    }

    fn call_function_param_after_expr(&mut self, index: usize
        , call_context: &mut GrammarCallFunctionContext) {
        self.handle_call_function_param_after_expr(index, call_context);
    }

    fn call_function(&mut self
        , param_len: usize, call_context: GrammarCallFunctionContext) -> DescResult {
        self.handle_call_function(param_len, call_context)
    }

    fn var_stmt_start(&mut self) {
        self.handle_var_stmt_start();
    }

    fn var_stmt_end(&mut self, context: VarStmtContext) {
        self.handle_var_stmt_end(context);
    }

    fn return_stmt(&mut self, context: GrammarReturnStmtContext) -> DescResult {
        self.handle_return_stmt(context);
        DescResult::Success
    }

    fn anonymous_block_start(&mut self) {
        self.process_anonymous_block_start();
    }

    fn anonymous_block_end(&mut self) {
        self.process_anonymous_block_end();
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
            compile_context: CompileContext::default(),
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
mod process_var;
mod process_return;
mod variant;
mod block;

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
