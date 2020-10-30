use libcommon::ptr::{HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::grammar::{BlockDefineContext, IfStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn if_process(&mut self) {
        /*
         * 跳过 if 关键字
         * */
        self.skip_next_one();
        /*
         * 解析表达式
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                /*
                 * if 后面没有token
                 *  => if 语句后面必须要有表达式
                 * */
                self.panic("expect expr, but arrive IOEof");
                return;
            }
        };
        let mut stmt_context = IfStmtContext::default();
        let mut define_context = BlockDefineContext::default();
        check_desc_result!(self, self.cb().if_stmt_start(&mut stmt_context, &mut define_context));
        check_desc_result!(self, self.cb().if_stmt_condition_branch_start(
                &mut stmt_context, &mut define_context));
        check_desc_result!(self, self.cb().if_stmt_expr_start(&mut stmt_context, &mut define_context));
        self.expression_process(&tp
            , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_left_big_parenthese));
        check_desc_result!(self, self.cb().if_stmt_expr_end(&mut stmt_context, &mut define_context));
        /*
         * 解析 block
         * */
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        check_desc_result!(self, self.cb().block_define_start(&mut define_context));
        self.parse_block_content();
        /*
         * 到达这里说明 next token 是 } => 跳过 `}`
         * */
        self.skip_next_one();
        check_desc_result!(self, self.cb().block_define_end(&mut define_context));
        check_desc_result!(self, self.cb().if_stmt_condition_branch_end(
                &mut stmt_context, &mut define_context));
        /*
         * 查看下一个 token 是 else_if 还是 else 或者 都不是
         * */
        check_desc_result!(self, self.process_after_if_brach(&mut stmt_context));
        check_desc_result!(self, self.cb().if_stmt_end(&mut stmt_context, &mut define_context));
    }

    fn process_else(&mut self, stmt_context: &mut IfStmtContext) -> DescResult {
        let mut define_context = BlockDefineContext::default();
        check_desc_result!(self, self.cb().if_stmt_else_branch_start(stmt_context, &mut define_context));
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        check_desc_result!(self, self.cb().block_define_start(&mut define_context));
        self.parse_block_content();
        self.skip_next_one();
        check_desc_result!(self, self.cb().block_define_end(&mut define_context));
        check_desc_result!(self, self.cb().if_stmt_else_branch_end(stmt_context, &mut define_context));
        DescResult::Success
    }

    fn process_else_if(&mut self, stmt_context: &mut IfStmtContext) -> DescResult {
        /*
         * 跳过 if 关键字
         * */
        self.skip_next_one();
        let mut define_context = BlockDefineContext::default();
        /*
         * 解析表达式
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                /*
                 * if 后面没有token
                 *  => if 语句后面必须要有表达式
                 * */
                self.panic("expect expr, but arrive IOEof");
                panic!();
            }
        };
        check_desc_result!(self, self.cb().if_stmt_condition_branch_start(
                stmt_context, &mut define_context));
        check_desc_result!(self, self.cb().if_stmt_expr_start(stmt_context, &mut define_context));
        self.expression_process(&tp
            , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_left_big_parenthese));
        check_desc_result!(self, self.cb().if_stmt_expr_end(stmt_context, &mut define_context));
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        check_desc_result!(self, self.cb().block_define_start(&mut define_context));
        self.parse_block_content();
        self.skip_next_one();
        check_desc_result!(self, self.cb().block_define_end(&mut define_context));
        check_desc_result!(self, self.cb().if_stmt_condition_branch_end(
                stmt_context, &mut define_context));
        /*
         * 查看下一个 token 是 else if / else / 都不是
         * */
        self.process_after_if_brach(stmt_context);
        DescResult::Success
    }

    fn process_after_if_brach(&mut self, stmt_context: &mut IfStmtContext) -> DescResult {
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                /*
                 * if 语句后是文件结尾 => 不处理
                 * */
                return DescResult::Success;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::Else => {
                self.skip_next_one();
            },
            TokenType::ElseIf => {
                /*
                 * elif 语句
                 * */
                return self.process_else_if(stmt_context);
            },
            _ => {
                /*
                 * 后面不是 else 开头的 => 整个 if 语句结束
                 * */
                return DescResult::Success;
            }
        }
        /*
         * 判断下一个是 if 还是 {
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                /*
                 * if 语句后是文件结尾 => 不处理
                 * */
                return DescResult::Success;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::If => {
                /*
                 * else if 语句
                 * */
                return self.process_else_if(stmt_context);
            },
            TokenType::LeftBigParenthese => {
                /*
                 * else 语句
                 * */
                return self.process_else(stmt_context);
            },
            _ => {
                /*
                 * else 后面既不是 { 也不是 if => 语法错误
                 * */
                return DescResult::Error(
                    format!("expect `{}` / if, but meet {:?}", "{", next.context_token_type()));
            }
        }
    }
}
