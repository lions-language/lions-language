use libcommon::ptr::{HeapPtr};
use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenValue};
use crate::grammar::{FunctionDefineContext
    , ObjectFunctionDefineMutContext
    , FunctionDefineParamMutContext
    , FunctionDefineParamContext
    , FunctionDefineParamContextType};
  
impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn function_object_method(&mut self) {
        let mut define_context = FunctionDefineContext::new_with_all(false, HeapPtr::new_null());
        /*
         * 读取 object name
         * */
        let object_name = self.take_next_one();
        /*
         * 跳过 : 号
         * */
        self.skip_next_one();
        /*
         * 解析类型
         * */
        let (typ_attr, lengthen_attr, typ_token) = self.typ_parse();
        /*
         * 查找 结束的 ]
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            match token.context_ref().token_type() {
                TokenType::RightSquareBrackets => {
                    parser.skip_next_one();
                },
                _ => {
                    parser.panic(
                        &format!("expect a `]`, and make `[` closed, but found {:?}"
                            , token.context_ref().token_type()));
                }
            }
        }, "a `]`, and make `[` closed");
        /*
         * 查看下一个是否是 id
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            match token.context_ref().token_type() {
                TokenType::Id => {
                },
                _ => {
                }
            }
        }, "id of function name");
        /*
         * 语法正确的情况下, next token 是函数名称
         * */
        let function_name = self.take_next_one();
        let mut mut_context = ObjectFunctionDefineMutContext::default();
        self.cb().function_object_method_stmt(
            typ_token, function_name.token_value(), &mut mut_context
            , &mut define_context);
        /*
         * 成员方法的第一个参数就是结构体实例, 所以需要添加第一个参数
         * */
        let mut param_mut_context = FunctionDefineParamMutContext::default();
        self.grammar_context().cb.function_define_param(
            FunctionDefineParamContext::new_with_all(
                object_name.token_value(), FunctionDefineParamContextType::Typ(mut_context.typ())
                , typ_attr, lengthen_attr, 0), &mut param_mut_context
                , &mut define_context);
        /*
         * 添加其余参数
         * */
        self.function_parse_param_list(1, &mut define_context, &mut param_mut_context);
        self.function_parse_return(&mut define_context);
        self.function_parse_block(&mut define_context);
    }

    pub fn function_struct_method(&mut self) {
    }

    pub fn function_method(&mut self) {
        /*
         * 结构体成员方法的定义
         * */
        /*
         * 跳过 [
         * */
        self.skip_next_one();
        /*
         * func [Type]()
         * func [self: Type]()
         * 通过 冒号来判断是 结构方法, 还是成员方法的定义
         * 1. 因为 : 号之前的一定是名称, 所以先取一个token
         * 2. 取出第一个token之后, 如果下一个是 :号, 说明是成员方法
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 至少需要一个token, 在 [ 之后, 但是遇到了 IO EOF => 语法错误
                 * */
                self.panic("at least one token is required, but arrive IO EOF");
                return;
            }
        };
        /*
         * 如果 [ 后面直接就是 ] => 语法错误
         * */
        let next_token = tp.as_ref::<T, CB>();
        if let TokenType::RightSquareBrackets = next_token.context_ref().token_type() {
            self.panic("must not be empty between `[]`");
        }
        /*
         * 虚拟跳过 [ 后面的第一个 token
         * */
        self.set_backtrack_point();
        self.virtual_skip_next_one();
        /*
         * 判断 [ 后的 第二个 token 是不是 : 号
         * */
        self.virtual_expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            /*
             * [ 后的第二个 token:
             *  `]` 或者 `:` 或者是类型中包含的 token, [std::net::HttpClient]
             * => 只要不是 `:`, 就不是成员方法
             * */
            /*
             * 先回到回溯点
             * */
            parser.restore_from_backtrack_point();
            match token.context_ref().token_type() {
                TokenType::Colon => {
                    /*
                     * 成员方法
                     * */
                    parser.function_object_method();
                },
                _ => {
                    /*
                     * 结构体方法
                     * */
                    parser.function_struct_method();
                }
            }
        }, "`]` or `:` or type token after `[`");
    }
}

