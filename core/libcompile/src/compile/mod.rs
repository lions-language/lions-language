use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddrValue};
use libgrammar::grammar::{Grammar, CallFuncScopeContext
    , VarStmtContext, LoadVariantContext as GrammarLoadVariantContext
    , ConstNumberContext, ConstStringContext, ConstBooleanContext
    , CallFunctionContext as GrammarCallFunctionContext
    , StructInitContext as GrammarStructInitContext
    , StructInitFieldContext
    , FunctionDefineParamContext
    , FunctionDefineParamMutContext
    , FunctionDefineReturnContext
    , FunctionDefineContext
    , BlockDefineContext
    , IfStmtContext
    , StructDefineFieldContext
    , ReturnStmtContext as GrammarReturnStmtContext
    , ObjectFunctionDefineMutContext, TypeToken
    , EnterPointAccessContext, VarUpdateStmtContext
    , ValueUpdateStmtContext
    , OperatorEqualEqualContext, ImportStmtContext
    , RelmodStmtContext, ModuleStmtContext
    , UseStmtContext};
use libgrammar::token::{TokenValue};
use libtype::{Type, Data};
use libtype::function::{Function, CallFunctionParamAddr
    , CallFunctionReturnData
    , FunctionParamDataItem
    , FunctionReturn
    , FunctionReturnDataAttr
    , FunctionStatement};
use libtype::structure::{StructDefine};
use libtype::instruction::{
    Instruction, BlockDefine
    , Jump, RemoveOwnership
    , AddRefParamAddr
    , UpdateRefParamAddr
    , CallSelfFunction
    , CallPrimevalFunctionParamContext
    , ConditionStmt, DeleteData};
use libtypecontrol::function::FunctionControl;
use libtype::module::Module;
use libresult::*;
use libtype::{AddressKey, AddressValue};
use libtype::package::{PackageStr};
use libstructtype::structure::{StructControl};
use libmacro::{FieldGet, FieldGetClone, FieldGetMove, NewWithAll};
use std::collections::HashMap;
use crate::address;
use crate::address::PackageIndex;
use crate::static_dispatch::{StaticVariantDispatch};
use crate::module::ModuleStack;
use scope::context::ScopeContext;
use crate::define_dispatch::{function::FunctionStatementObject};
use crate::define::{DefineObject};

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
pub struct CallFunctionContext {
    pub package_str: PackageStr,
    pub func_define: libtype::function::FunctionDefine,
    pub param_addrs: Option<Vec<CallFunctionParamAddr>>,
    pub param_context: Option<Vec<CallPrimevalFunctionParamContext>>,
    pub call_param_len: usize,
    pub return_data: CallFunctionReturnData
}

#[derive(Debug, FieldGet, FieldGetMove)]
pub struct FunctionNamedStmtContext {
    name: String,
    typ: Option<Type>
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
    addr_value: AddressValue
}

trait TokenValueExpand {
    // fn to_type(&self) -> Type;
    fn to_data(self) -> Data;
}

trait AddressValueExpand {
    fn add_scope(&mut self, n: usize);
    fn clone_with_index_plus(&self, n: usize) -> AddressValue;
    fn clone_with_scope_plus(&self, n: usize) -> AddressValue;
    fn clone_with_scope_minus(&self, n: usize) -> AddressValue;
    fn addr_with_scope_minus(self, n: usize) -> AddressValue;
    fn addr_with_scope_plus(self, n: usize) -> AddressValue;
    fn addr_mut_with_scope_minus(&mut self, n: usize);
    fn addr_mut_with_scope_plus(&mut self, n: usize);
}

trait TypeTokenExpand {
    fn to_type<F: Compile>(self, compiler: RefPtr) -> Result<Type, DescResult>;
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

    fn call_self_function(&mut self, context: CallSelfFunction) {
        unimplemented!();
    }

    fn function_named_stmt(&mut self, _context: FunctionNamedStmtContext
        , _define_context: &mut FunctionDefineContext) -> RefPtr {
        unimplemented!();
    }

    fn function_push_param_to_statement(&mut self
        , _item: FunctionParamDataItem
        , _define_context: &FunctionDefineContext) {
    }

    fn function_set_return_to_statement(&mut self
        , _item: FunctionReturn
        , _define_context: &FunctionDefineContext) {
    }

    fn function_define_start(&mut self) {
        println!("function define start");
    }

    fn current_function_statement(&self
        , _define_obj: DefineObject) -> Option<FunctionStatementObject> {
        unimplemented!();
    }

    fn current_function_addr_value(&self
        , _define_obj: DefineObject) -> FunctionAddrValue {
        unimplemented!();
    }

    fn function_define_end(&mut self
        , _define_context: &FunctionDefineContext) -> Function {
        unimplemented!();
    }

    fn enter_block_define(&mut self, _define_context: &mut BlockDefineContext) {
    }

    fn current_block_addr_value(&self, _define_obj: DefineObject) -> FunctionAddrValue {
        unimplemented!();
    }

    fn leave_block_define(&mut self, _define_obj: DefineObject) -> FunctionAddrValue {
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

    fn condition_stmt(&mut self, _context: ConditionStmt) {
        unimplemented!();
    }

    fn current_index(&self) -> usize {
        unimplemented!();
    }

    fn update_instructure_by_index(&mut self, index: usize, ins: Instruction) {
        unimplemented!();
    }

    fn get_current_instructure_ptr(&self, index: usize) -> RefPtr {
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

    fn delete_data(&mut self, _context: DeleteData) {
        unimplemented!();
    }

    fn update_func_return_data_addr(&mut self, _: FunctionReturnDataAttr
        , _define_obj: DefineObject) {
        unimplemented!();
    }

    fn add_ref_param_addr(&mut self, _: AddRefParamAddr) {
        unimplemented!();
    }

    fn update_ref_param_addr(&mut self, _: UpdateRefParamAddr) {
        unimplemented!();
    }

    fn execute_block(&mut self, _: BlockDefine) {
        unimplemented!();
    }
}

pub enum FileType {
    Main,
    Mod,
    RELMOD
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

pub struct ImportData {
}

pub struct Compiler<'a, F: Compile> {
    function_control: FunctionControl,
    struct_control: StructControl,
    module: &'a Module,
    scope_context: ScopeContext,
    input_context: InputContext,
    package_index: &'a mut PackageIndex,
    static_variant_dispatch: &'a mut StaticVariantDispatch<'a>,
    package_str: &'a str,
    compile_context: CompileContext,
    vm_scope_value: usize,
    cb: &'a mut F,
    import_datas: HashMap<String, ImportData>
}

impl<'a, F: Compile> Grammar for Compiler<'a, F> {
    fn const_number(&mut self, context: ConstNumberContext) {
	self.const_number(context);
    }

    fn const_string(&mut self, context: ConstStringContext) {
        self.handle_const_string(context);
    }

    fn const_boolean(&mut self, context: ConstBooleanContext) {
        self.process_const_boolean(context);
    }

    fn load_variant(&mut self, context: GrammarLoadVariantContext) -> DescResult {
        self.handle_load_variant(context)
    }

    fn operator_plus(&mut self, value: TokenValue) -> DescResult {
        self.operator_plus(value)
    }

    fn operator_equal_equal(&mut self, context: OperatorEqualEqualContext) -> DescResult {
        self.operator_equal_equal(context)
    }

    fn end(&mut self) -> DescResult {
        self.handle_end()
    }

    fn function_named_stmt(&mut self, value: TokenValue
        , define_context: &mut FunctionDefineContext) -> DescResult {
        self.handle_function_named_stmt(value, define_context)
    }
    
    fn function_object_method_stmt(&mut self
        , object_type: TypeToken, func_name: TokenValue
        , mut_context: &mut ObjectFunctionDefineMutContext
        , define_context: &mut FunctionDefineContext) -> DescResult {
        self.handle_function_object_method_stmt(object_type
            , func_name, mut_context, define_context)
    }

    fn function_define_start(&mut self, _value: TokenValue) {
        self.handle_function_define_start();
    }

    fn function_define_param(&mut self, context: FunctionDefineParamContext
        , mut_context: &mut FunctionDefineParamMutContext
        , define_context: &mut FunctionDefineContext) -> DescResult {
        self.handle_function_define_param(context, mut_context, define_context)
    }

    fn function_define_return(&mut self, context: FunctionDefineReturnContext
        , define_context: &mut FunctionDefineContext) -> DescResult {
        self.handle_function_define_return(context, define_context)
    }

    fn function_define_end(&mut self, _value: TokenValue
        , define_context: &FunctionDefineContext) {
        self.handle_function_define_end(define_context);
    }

    fn block_define_start(&mut self
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_block_define_start(define_context)
    }

    fn block_define_end(&mut self
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_block_define_end(define_context)
    }

    fn call_function_prepare(&mut self, scope_context: CallFuncScopeContext
        , call_context: &mut GrammarCallFunctionContext) -> DescResult {
        self.handle_call_function_prepare(scope_context, call_context)
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

    fn var_stmt_end(&mut self, context: VarStmtContext) -> DescResult {
        self.handle_var_stmt_end(context)
    }

    fn var_update_stmt(&mut self, context: VarUpdateStmtContext) -> DescResult {
        self.handle_var_update_stmt(context)
    }

    fn value_update_stmt(&mut self, context: ValueUpdateStmtContext) -> DescResult {
        self.handle_value_update_stmt(context)
    }

    fn return_stmt(&mut self, context: GrammarReturnStmtContext) -> DescResult {
        self.handle_return_stmt(context)
    }
    
    fn if_stmt_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_start(stmt_context, define_context)
    }

    fn if_stmt_else_branch_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_else_branch_start(stmt_context, define_context)
    }

    fn if_stmt_condition_branch_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_condition_branch_start(stmt_context, define_context)
    }

    fn if_stmt_expr_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_expr_start(stmt_context, define_context)
    }

    fn if_stmt_expr_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_expr_end(stmt_context, define_context)
    }

    fn if_stmt_condition_branch_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_condition_branch_end(stmt_context, define_context)
    }

    fn if_stmt_else_branch_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_else_branch_end(stmt_context, define_context)
    }

    fn if_stmt_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.process_if_stmt_end(stmt_context, define_context)
    }

    fn anonymous_block_start(&mut self) {
        self.process_anonymous_block_start();
    }

    fn anonymous_block_end(&mut self) {
        self.process_anonymous_block_end();
    }

    fn struct_define_start(&mut self, define: &mut StructDefine) {
        self.process_struct_define_start(define);
    }

    fn struct_define_field(&mut self, context: StructDefineFieldContext
        , define: &mut StructDefine) -> DescResult {
        self.process_struct_define_field(context, define)
    }

    fn struct_define_end(&mut self, define: StructDefine) {
        self.process_struct_define_end(define);
    }

    fn struct_init_start(&mut self, init_context: &mut GrammarStructInitContext) -> DescResult {
        self.process_struct_init_start(init_context)
    }

    fn struct_init_field_before_expr(&mut self, init_context: &mut GrammarStructInitContext
        , field_context: StructInitFieldContext) -> DescResult {
        self.process_struct_init_field_before_expr(init_context, field_context)
    }

    fn struct_init_field_after_expr(&mut self, init_context: &mut GrammarStructInitContext)
        -> DescResult {
        self.process_struct_init_field_after_expr(init_context)
    }

    fn struct_init_end(&mut self, init_context: &mut GrammarStructInitContext) -> DescResult {
        self.process_struct_init_end(init_context)
    }

    fn enter_point_access(&mut self, context: EnterPointAccessContext) {
        self.process_enter_point_access(context);
    }

    fn leave_point_access(&mut self) {
        self.process_leave_point_access();
    }

    fn import_stmt(&mut self, context: ImportStmtContext) -> DescResult {
        self.process_import_stmt(context)
    }

    fn relmod_stmt(&mut self, context: RelmodStmtContext) -> DescResult {
        self.process_relmod_stmt(context)
    }

    fn module_stmt(&mut self, context: ModuleStmtContext) -> DescResult {
        self.process_module_stmt(context)
    }

    fn use_stmt(&mut self, context: UseStmtContext) -> DescResult {
        self.process_use_stmt(context)
    }
}

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn new(module: &'a Module, cb: &'a mut F, input_context: InputContext
        , package_index: &'a mut PackageIndex
        , static_variant_dispatch: &'a mut StaticVariantDispatch<'a>
        , package_str: &'a str) -> Self {
        Self {
            function_control: FunctionControl::new(),
            struct_control: StructControl::new(),
            module: module,
            scope_context: ScopeContext::new(),
            input_context: input_context,
            package_index: package_index,
            static_variant_dispatch: static_variant_dispatch,
            package_str: package_str,
            compile_context: CompileContext::default(),
            vm_scope_value: 0,
            cb: cb,
            import_datas: HashMap::new()
        }
    }
}

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
mod structure;
mod structinit;
mod point_access;
mod process_if;
mod boolean;
mod import;
mod relmod;
mod process_module;
mod package;
mod process_use;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::lexical::IoAttribute;
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
        let io_attr = IoAttribute::new_with_all(1);
        let lexical_parser = LexicalParser::new(file.clone(), io_attr.clone()
            , || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let f_ref = f.by_ref();
            match f_ref.take(io_attr.read_once_max_clone() as u64).read_to_end(&mut v) {
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
        let module = Module::new(String::from("main"));
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(&module
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
