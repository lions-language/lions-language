use libtype::AddressValue;
use crate::lexical::{LexicalParser, CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue, TokenMethodResult};
use libcommon::ptr::{RefPtr, HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libcommon::consts::{ImportPrefixType};
use libtype::{Type, TypeAttrubute
    , function::FunctionParamLengthenAttr
    , structure::StructDefine};
use libtype::function::{FindFunctionHandle};
use libresult::*;
use libtype::package::PackageStr;
use libmacro::{FieldGet, NewWithAll
    , FieldGetMove, FieldGetClone};

#[derive(FieldGet, FieldGetClone
    , FieldGetMove)]
pub struct CallFuncScopeContext {
    module_prefix: Option<String>,
    desc_ctx: DescContext
}

#[derive(FieldGet)]
pub struct VarStmtContext {
    id_token: TokenValue,
    is_exist_equal: bool
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetMove)]
pub struct VarUpdateStmtContext {
    /*
     * 如果没有, 说明是对 xxx.xxx 的形式
     * */
    name: Option<String>
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetMove)]
pub struct ValueUpdateStmtContext {
}

impl Default for VarStmtContext {
    fn default() -> Self {
        Self {
            id_token: TokenValue::default(),
            is_exist_equal: false
        }
    }
}

pub enum LoadVariantContextValue {
    Single(TokenValue)
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct LoadVariantContext {
    first: TokenValue,
    other: Option<Vec<TokenValue>>,
    typ_attr: TypeAttrubute,
    lengthen_offset: usize
}

#[derive(Debug, FieldGet, FieldGetClone
    , NewWithAll, FieldGetMove
    , Default)]
pub struct CallFunctionContext {
    func_ptr: RefPtr,
    package_str: PackageStr,
    module_str: Option<String>,
    typ: Option<Type>,
    func_name: Option<String>,
    param_typs: Vec<(Type, TypeAttrubute)>,
    desc_ctx: DescContext
}

impl CallFunctionContext {
    pub fn set_func_ptr(&mut self, func_ptr: RefPtr) {
        *&mut self.func_ptr = func_ptr;
    }
    pub fn set_package_str(&mut self,  package_str: PackageStr) {
        *&mut self.package_str = package_str;
    }
    pub fn set_module_str(&mut self, module_str: Option<String>) {
        *&mut self.module_str = module_str;
    }
    pub fn set_typ(&mut self, typ: Option<Type>) {
        *&mut self.typ = typ;
    }
    pub fn set_func_name(&mut self, func_name: String) {
        *&mut self.func_name = Some(func_name);
    }
    pub fn push_param_typ(&mut self
        , typ: Type, typ_attr: TypeAttrubute) {
        self.param_typs.push((typ, typ_attr));
    }
    pub fn set_desc_ctx(&mut self, desc_ctx: DescContext) {
        *&mut self.desc_ctx = desc_ctx;
    }
    pub fn func_name_ref_unchecked(&self) -> &str {
        self.func_name.as_ref().expect("CallFunctionContext func_name_ref_unchecked should not happend")
    }
}

#[derive(Debug, FieldGet, FieldGetClone
    , NewWithAll, FieldGetMove
    , Default)]
pub struct StructInitContext {
    struct_name: String,
    define: HeapPtr,
    desc_ctx: DescContext
}

#[derive(Debug, FieldGet, NewWithAll, FieldGetMove
    , FieldGetClone
    , Clone)]
pub struct DescContext {
    typ_attr: TypeAttrubute,
    star_prefix: bool
}

impl Default for DescContext {
    fn default() -> Self {
        Self {
            typ_attr: TypeAttrubute::default(),
            star_prefix: false
        }
    }
}

impl DescContext {
    pub fn new(typ_attr: TypeAttrubute) -> Self {
        DescContext::new_with_all(typ_attr, false)
    }
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct ConstNumberContext {
    value: TokenValue,
    typ_attr: TypeAttrubute
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct ConstStringContext {
    value: TokenValue,
    typ_attr: TypeAttrubute
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct ConstBooleanContext {
    value: TokenValue,
    typ_attr: TypeAttrubute
}

#[derive(Debug)]
pub enum FunctionDefineParamContextType {
    Token(TypeToken),
    Typ(Type)
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct FunctionDefineParamContext {
    name_token: TokenValue,
    type_token: FunctionDefineParamContextType,
    typ_attr: TypeAttrubute,
    lengthen_attr: FunctionParamLengthenAttr,
    /*
     * 参数序号
     * */
    param_no: usize
}

#[derive(Default, FieldGet, NewWithAll, FieldGetMove
    , FieldGetClone)]
pub struct FunctionDefineParamMutContext {
    /*
     * 引用参数序号
     * */
    ref_param_no: usize
}

#[derive(Debug, FieldGet, NewWithAll, FieldGetMove)]
pub struct FunctionDefineReturnContext {
    typ_attr: TypeAttrubute,
    lengthen_attr: FunctionParamLengthenAttr,
    type_token: TypeToken
}

#[derive(Debug, Default, FieldGet, NewWithAll, FieldGetMove
    , FieldGetClone)]
pub struct FunctionDefineContext {
    has_lengthen_param: bool,
    define_obj: HeapPtr
}

#[derive(Debug, Default, FieldGet, NewWithAll, FieldGetMove
    , FieldGetClone)]
pub struct BlockDefineContext {
    define_obj: HeapPtr,
    define_addr: FunctionAddrValue
}

#[derive(Debug, Default, FieldGet, NewWithAll, FieldGetMove
    , FieldGetClone)]
pub struct StructDefineContext {
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct StructDefineFieldContext {
    name_token: TokenValue,
    type_token: TypeToken,
    typ_attr: TypeAttrubute
}

#[derive(FieldGet, NewWithAll, FieldGetMove)]
pub struct StructInitFieldContext {
    name_token: TokenValue
}

#[derive(Debug)]
pub enum TypeToken {
    Single(TokenValue),
    Multi,
    Tuple,
}

#[derive(Debug, FieldGet, NewWithAll, FieldGetMove
    , FieldGetClone)]
pub struct ReturnStmtContext {
    is_exist_expr: bool
}

#[derive(Debug, Clone, Default
    , FieldGet, FieldGetClone)]
pub struct IfStmtContext {
    cur_expr_result_addr: AddressValue,
    /*
     * 如果是 if, 那么 last 就是 None
     * */
    last_condition_instruction_index: Option<usize>,
    condition_instructure_indexs: Vec<usize>
}

#[derive(Debug, FieldGet, FieldGetClone
    , NewWithAll, FieldGetMove
    , Default)]
pub struct ObjectFunctionDefineMutContext {
    typ: Type
}

#[derive(Debug, FieldGet, FieldGetClone
    , NewWithAll, FieldGetMove
    , Default)]
pub struct EnterPointAccessContext {
    object_typ_attr: TypeAttrubute
}

#[derive(Debug, FieldGet
    , NewWithAll, FieldGetMove
    , Default)]
pub struct OperatorEqualEqualContext {
    value: TokenValue,
    desc_ctx: DescContext
}

#[derive(Debug, Default)]
pub struct ImportStmtContext<'a> {
    pub prefix: ImportPrefixType,
    pub content: &'a str,
    pub alias: Option<String>
}

#[derive(Debug, FieldGet
    , NewWithAll, FieldGetMove
    , Default)]
pub struct RelmodStmtContext {
    pub content: String
}

#[derive(Debug, FieldGet
    , NewWithAll, FieldGetMove
    , Default)]
pub struct ModuleStmtContext {
    pub module_name: String,
    pub available_stmt_count: usize,
    pub counter_len: usize
}

#[derive(Debug, FieldGet
    , NewWithAll, FieldGetMove
    , Default)]
pub struct UseStmtContext {
    pub content: String
}

impl<'a> ImportStmtContext<'a> {
    pub fn new(prefix: ImportPrefixType, content: &'a str
        , alias: Option<String>) -> Self {
        Self {
            prefix: prefix,
            content: content,
            alias: alias
        }
    }
}

#[derive(Debug, FieldGet
    , NewWithAll, FieldGetMove
    , Default)]
pub struct EndContext {
    counter_len: usize
}

#[derive(Debug, FieldGet
    , NewWithAll, FieldGetMove
    , Default)]
pub struct FirstStmtContext {
}

pub trait Grammar {
    // type IdUse;
    
    fn const_number(&mut self, context: ConstNumberContext) {
        context.value.print_token_type(None);
    }
    fn const_string(&mut self, context: ConstStringContext) {
        context.value.print_token_type(None);
    }
    fn const_boolean(&mut self, _context: ConstBooleanContext) {
        unimplemented!();
    }
    fn load_variant(&mut self, _context: LoadVariantContext) -> DescResult {
        println!("load variant");
        DescResult::Success
    }
    fn annotate(&mut self, _value: TokenValue) {
        println!("annotate");
    }
    fn operator_plus(&mut self, value: TokenValue) -> DescResult {
        value.print_token_type(None);
        DescResult::Success
    }
    fn operator_equal(&mut self, value: TokenValue) -> DescResult {
        unimplemented!();
    }
    fn operator_equal_equal(&mut self, context: OperatorEqualEqualContext) -> DescResult {
        unimplemented!();
    }
    fn operator_prefix_increase(&mut self, value: TokenValue) {
        value.print_token_type(Some("prefix increase:"));
    }
    fn operator_suffix_increase(&mut self, value: TokenValue) {
        value.print_token_type(Some("suffix increase:"));
    }
    fn operator_multiplication(&mut self, value: TokenValue) {
        value.print_token_type(None);
    }
    fn operator_minus(&mut self, value: TokenValue) {
        value.print_token_type(None);
    }
    fn operator_negative(&mut self, value: TokenValue) {
        value.print_token_type(Some("prefix operator:"));
    }
    fn operator_positive(&mut self, value: TokenValue) {
        value.print_token_type(Some("prefix operator:"));
    }
    fn function_named_stmt(&mut self, _func_name: TokenValue
        , _define_context: &mut FunctionDefineContext) -> DescResult {
        unimplemented!();
    }
    fn function_object_method_stmt(&mut self
        , _object_type: TypeToken, _function_name: TokenValue
        , _mut_context: &mut ObjectFunctionDefineMutContext
        , _define_context: &mut FunctionDefineContext) -> DescResult {
        unimplemented!("function_object_memthod_stmt");
    }
    fn function_struct_method_stmt(&mut self) {
    }
    fn function_define_start(&mut self, _value: TokenValue) {
        /*
         * 命名函数函数体开始
         * */
        println!("named function define start");
    }
    fn function_define_param(&mut self, context: FunctionDefineParamContext
        , _mut_context: &mut FunctionDefineParamMutContext
        , _define_context: &mut FunctionDefineContext) -> DescResult {
        unimplemented!();
    }
    fn function_define_return(&mut self, _context: FunctionDefineReturnContext
        , _define_context: &mut FunctionDefineContext) -> DescResult {
        unimplemented!();
    }
    fn function_define_end(&mut self, _value: TokenValue
        , _define_context: &FunctionDefineContext) {
        /*
         * 命名函数函数体结束
         * */
        println!("named function define end");
    }
    fn block_define_start(&mut self, _define_context: &mut BlockDefineContext)
        -> DescResult {
        unimplemented!();
    }
    fn block_define_end(&mut self, _define_context: &mut BlockDefineContext)
        -> DescResult {
        unimplemented!();
    }
    fn call_function_prepare(&mut self, _context: CallFuncScopeContext
        , _: &mut CallFunctionContext) -> DescResult {
        DescResult::Success
    }
    fn call_function_param_before_expr(&mut self, _index: usize
        , _: &mut CallFunctionContext) {
    }
    fn call_function_param_after_expr(&mut self, _index: usize
        , _: &mut CallFunctionContext) {
    }
    fn call_function(&mut self
        , _param_len: usize
        , _: CallFunctionContext)
        -> DescResult {
        DescResult::Success
    }
    fn struct_define_start(&mut self, _: &mut StructDefine) {
        unimplemented!();
    }
    fn struct_define_field(&mut self, _: StructDefineFieldContext
        , _: &mut StructDefine) -> DescResult {
        unimplemented!();
    }
    fn struct_define_end(&mut self, _: StructDefine) {
        unimplemented!();
    }
    fn struct_init_start(&mut self, _: &mut StructInitContext) -> DescResult {
        unimplemented!();
    }
    fn struct_init_field_before_expr(&mut self, _: &mut StructInitContext
        , _: StructInitFieldContext) -> DescResult {
        unimplemented!();
    }
    fn struct_init_field_after_expr(&mut self, _: &mut StructInitContext)
        -> DescResult {
        unimplemented!();
    }
    fn struct_init_end(&mut self, _: &mut StructInitContext) -> DescResult {
        unimplemented!();
    }
    fn var_stmt_start(&mut self) {
        println!("var stmt start");
    }
    fn var_stmt_end(&mut self, _context: VarStmtContext) -> DescResult {
        unimplemented!("var stmt end");
    }
    fn var_update_stmt(&mut self, _context: VarUpdateStmtContext) -> DescResult {
        unimplemented!();
    }
    fn value_update_stmt(&mut self, _context: ValueUpdateStmtContext) -> DescResult {
        unimplemented!();
    }
    fn return_stmt(&mut self, _context: ReturnStmtContext) -> DescResult {
        println!("return stmt");
        DescResult::Success
    }
    fn if_stmt_start(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * 整个 if 语句开始
         * */
        unimplemented!();
    }
    fn if_stmt_expr_start(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * if 语句 过程中的 表达式开始
         * */
        unimplemented!();
    }
    fn if_stmt_expr_end(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        unimplemented!();
    }
    fn if_stmt_condition_branch_start(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * if语句中的 分支 开始
         * */
        unimplemented!();
    }
    fn if_stmt_condition_branch_end(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * if语句中的 分支 结束
         * */
        unimplemented!();
    }
    fn if_stmt_else_branch_start(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * if语句中的 分支 开始
         * */
        unimplemented!();
    }
    fn if_stmt_else_branch_end(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * if语句中的 分支 结束
         * */
        unimplemented!();
    }
    fn if_stmt_end(&mut self, _stmt_context: &mut IfStmtContext
        , _define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * 整个 if 语句的结束
         * */
        unimplemented!();
    }
    fn anonymous_block_start(&mut self) {
        println!("anonymous block start");
    }
    fn anonymous_block_end(&mut self) {
        println!("anonymous block end");
    }
    fn end(&mut self, _context: EndContext) -> DescResult {
        DescResult::Success
    }
    fn enter_point_access(&mut self, _context: EnterPointAccessContext) {
        unimplemented!();
    }
    fn leave_point_access(&mut self) {
        unimplemented!();
    }
    fn import_stmt(&mut self, _context: ImportStmtContext) -> DescResult {
        unimplemented!();
    }
    fn relmod_stmt(&mut self, _context: RelmodStmtContext) -> DescResult {
        unimplemented!();
    }
    fn module_stmt(&mut self, _context: ModuleStmtContext) -> DescResult {
        unimplemented!();
    }
    fn use_stmt(&mut self, _context: UseStmtContext) -> DescResult {
        unimplemented!();
    }
    fn first_stmt(&mut self, _context: FirstStmtContext) -> DescResult {
        unimplemented!();
    }
}

enum NextToken<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    True(TokenVecItem<T, CB>),
    False(TokenPointer)
}

pub struct GrammarContext<CB>
    where CB: Grammar {
    pub cb: CB
}

pub type ExpressEndFunc<T, CB> = fn(&mut GrammarParser<T, CB>, &TokenVecItem<T, CB>) -> TokenMethodResult;
/*
 * return:
 *  true: 解析结束
 *  false: 解析继续
 * */
pub type ParserEndFunc<T, CB> = fn(&mut GrammarParser<T, CB>, &Option<TokenPointer>) -> bool;

pub struct ExpressContext<T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    pub end_f: ExpressEndFunc<T, CB>,
    desc_ctx: DescContext
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> ExpressContext<T, CB> {
    pub fn new_with_desc_ctx(end_f: ExpressEndFunc<T, CB>
        , desc_ctx: DescContext) -> Self {
        Self {
            end_f: end_f,
            desc_ctx: desc_ctx
        }
    }

    pub fn new(end_f: ExpressEndFunc<T, CB>) -> Self {
        ExpressContext::<T, CB>::new_with_desc_ctx(end_f
            , DescContext::new(TypeAttrubute::Move))
    }
}

#[derive(Default, FieldGet
    , FieldGetClone)]
struct StmtCounter {
    available_stmt_count: usize
}

pub struct GrammarParser<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> {
    lexical_parser: LexicalParser<T, CB>,
    context: &'a mut GrammarContext<CB>,
    counter_stack: libcommon::datastructure::stack::Stack<StmtCounter>
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn parser(&mut self) {
        self.parser_inner(|_, _| -> bool {
            false
        });
    }

    fn parser_inner(&mut self, cb: ParserEndFunc<T, CB>) {
        self.counter_stack.push(StmtCounter::default());
        loop {
            // match self.lexical_parser.lookup_next_one_ptr() {
            let tp = self.skip_white_space_token();
            if (cb)(self, &tp) {
                break;
            }
            match tp {
                Some(p) => {
                    self.select(&p);
                },
                None => {
                    let available_stmt_count =
                        self.counter_stack.top_ref_unchecked().available_stmt_count_clone();
                    match self.cb().end(EndContext::new_with_all(available_stmt_count)) {
                        DescResult::Error(e) => {
                            self.panic(&e);
                        },
                        _ => {
                            if self.counter_stack.top_ref_unchecked().available_stmt_count_clone() == 0 {
                                /*
                                 * 第一条语句
                                 * */
                                self.first_stmt_process();
                            }
                        }
                    }
                    break;
                }
            }
        }
        self.counter_stack.pop();
    }

    fn select_with_exprcontext(&mut self, token: &TokenPointer, express_context: &ExpressContext<T, CB>) {
        enum StmtType {
            Available,
            Annotate
        }
        let mut stmt_type = StmtType::Available;
        match token.as_ref::<T, CB>().context_ref().token_type() {
            TokenType::If => {
                self.if_process();
            },
            TokenType::Annotate => {
                self.annotate_process();
                stmt_type = StmtType::Annotate;
            },
            TokenType::Function => {
                self.function_process();
            },
            TokenType::Var => {
                self.var_process();
            },
            TokenType::Return => {
                self.return_process();
            },
            TokenType::Structure => {
                self.structure_process();
            },
            TokenType::Import => {
                self.import_process();
            },
            TokenType::Relmod => {
                self.relmod_process();
            },
            TokenType::Module => {
                self.module_process();
            },
            TokenType::Use => {
                self.use_process();
            },
            _ => {
                self.expression_process(token, express_context);
            }
        }
        match stmt_type {
            StmtType::Available => {
                if self.counter_stack.top_ref_unchecked().available_stmt_count_clone() == 0 {
                    /*
                     * 第一条语句
                     * */
                    self.first_stmt_process();
                }
                *self.counter_stack.top_mut_unchecked().available_stmt_count_mut() += 1;
            },
            StmtType::Annotate => {
            }
        }
    }

    fn select(&mut self, token: &TokenPointer) {
        self.select_with_exprcontext(token
            , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_normal));
    }

    fn token_is_white_space(&self, token: &TokenVecItem<T, CB>) -> bool {
        match token.context_ref().token_type() {
            TokenType::NewLine => {
                return true;
            },
            _ => {
                return false;
            }
        }
    }

    fn expect_and_take_next_token_unchecked(&mut self, token_type: TokenType)
        -> TokenVecItem<T, CB> {
        let tt = token_type.clone();
        match self.expect_and_take_next_token(token_type) {
            NextToken::<T, CB>::True(t) => {
                t
            },
            NextToken::<T, CB>::False(tp) => {
                let t = tp.as_ref::<T, CB>();
                self.panic(&format!(
                        "expect {:?}, but meet: {:?}"
                        , tt, t.context_token_type()));
                panic!();
            }
        }
    }

    fn expect_and_take_next_token(&mut self, token_type: TokenType) -> NextToken<T, CB> {
        /*
         * 注意: 该方法会先去除全部的空白
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 期望下一个 token, 但是遇到了 IO EOF => 语法错误
                 * */
                self.panic(&format!("expect {:?}, but arrive IO EOF", &token_type));
                panic!();
            }
        };
        let next = tp.as_ref::<T, CB>();
        if &token_type == next.context_token_type() {
            NextToken::<T, CB>::True(self.take_next_one())
        } else {
            NextToken::<T, CB>::False(tp)
        }
    }

    fn expect_next_token_unchecked<F>(&mut self, f: F
        , token_prompt: &'static str) -> TokenPointer
        where F: FnMut(&mut GrammarParser<T, CB>, TokenPointer) {
        self.expect_next_token(f, token_prompt).expect("should not happend")
    }

    fn expect_next_token<F>(&mut self, mut f: F, token_prompt: &'static str) -> Option<TokenPointer>
        /*
         * 注意: 该方法会先去除全部的空白
         * */
        where F: FnMut(&mut GrammarParser<T, CB>, TokenPointer) {
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 期望下一个 token, 但是遇到了 IO EOF => 语法错误
                 * */
                self.panic(&format!("expect {}, but arrive IO EOF", token_prompt));
                return None;
            }
        };
        /*
         * TokenPointer 中的 clone, 只是 地址的拷贝
         * */
        f(self, tp.clone());
        Some(tp)
    }

    fn virtual_expect_next_token<F>(&mut self
        , mut f: F, token_prompt: &'static str) -> Option<TokenPointer>
        where F: FnMut(&mut GrammarParser<T, CB>, TokenPointer) {
        let tp = match self.virtual_skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic(&format!("expect {}, but arrive IO EOF", token_prompt));
                return None;
            }
        };
        f(self, tp.clone());
        Some(tp)
    }

    fn cb(&mut self) -> &mut Grammar {
        &mut self.grammar_context().cb
    }

    /*
     * 跳过空白
     * 如果跳过所有的空白之后, 还有有效的 token, 将返回 Some(token), 否则返回 None
     * */
    pub fn skip_white_space_token(&mut self) -> Option<TokenPointer> {
        loop {
            let tp = match self.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    return None;
                }
            };
            let next = tp.as_ref::<T, CB>();
            if self.token_is_white_space(next) {
                self.skip_next_one();
            } else {
                return Some(tp);
            }
        }
    }

    pub fn virtual_skip_white_space_token(&mut self) -> Option<TokenPointer> {
        loop {
            let tp = match self.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    return None;
                }
            };
            let next = tp.as_ref::<T, CB>();
            if self.token_is_white_space(next) {
                self.virtual_skip_next_one();
            } else {
                return Some(tp);
            }
        }
    }

    pub fn skip_white_space_token_with_input(&mut self, input_tp: TokenPointer) -> Option<TokenPointer> {
        let input_token = input_tp.as_ref::<T, CB>();
        if self.token_is_white_space(input_token) {
            return self.skip_white_space_token();
        } else {
            return Some(input_tp);
        }
    }

    pub fn take_next_one(&mut self) -> TokenVecItem<T, CB> {
        self.lexical_parser.take_next_one()
    }

    pub fn skip_next_one(&mut self) {
        self.lexical_parser.skip_next_one();
    }

    pub fn skip_next_n(&mut self, n: usize) {
        self.lexical_parser.skip_next_n(n);
    }

    pub fn lookup_next_one_ptr(&mut self) -> Option<TokenPointer> {
        self.lexical_parser.lookup_next_one_ptr()
    }

    pub fn virtual_skip_next_n(&mut self, n: usize) {
        self.lexical_parser.virtual_skip_next_n(n);
    }

    pub fn virtual_skip_next_one(&mut self) {
        self.lexical_parser.virtual_skip_next_one();
    }

    pub fn set_backtrack_point(&mut self) {
        self.lexical_parser.set_backtrack_point();
    }

    pub fn restore_from_backtrack_point(&mut self) -> usize {
        self.lexical_parser.restore_from_backtrack_point()
    }

    pub fn backtrack_n(&mut self, n: usize) {
        self.lexical_parser.backtrack_n(n);
    }

    pub fn grammar_context(&mut self) -> &mut GrammarContext<CB> {
        self.context
    }

    pub fn panic(&self, msg: &str) {
        self.lexical_parser.panic(msg);
    }

    pub fn new(lexical_parser: LexicalParser<T, CB>,
            grammar_context: &'a mut GrammarContext<CB>) -> Self {
        Self {
            lexical_parser: lexical_parser,
            context: grammar_context,
            counter_stack: libcommon::datastructure::stack::Stack::new()
        }
    }
}

mod expression;
mod function;
mod id;
mod funccall;
mod token_extend;
mod annotate;
mod typesof;
mod process_var;
mod process_return;
mod block;
mod and;
mod number;
mod string;
mod typ;
mod structure;
mod structinit;
mod process_if;
mod boolean;
mod equal;
mod import;
mod relmod;
mod star;
mod module;
mod process_use;
mod process_first;

#[cfg(test)]
mod test {
    use super::*;
    use crate::lexical::VecU8;

    use std::fs;
    use std::io::Read;

    struct TestGrammar {
    }

    impl Grammar for TestGrammar {
    }

    #[test]
    // #[ignore]
    fn grammar_parser_test() {
        let mut file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(err) => {
                panic!("read file error");
            }
        };
        let mut lexical_parser = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let mut f_ref = f.by_ref();
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
            cb: TestGrammar{}
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}

