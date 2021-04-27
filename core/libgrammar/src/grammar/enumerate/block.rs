use libtype::{TypeAttrubute};
use libtype::interface::{InterfaceDefine};
use libtype::enumerate::{EnumerateDefine};
use crate::grammar::{GrammarParser, Grammar, NextToken, ExpressContext
    , EnumDefineStartContext, EnumDefineItemContext, EnumDefineEndContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue, TokenData};
use libresult::{DescResult};

enum Status {
    Continue,
    End
}

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn enum_block_process(&mut self, define: &mut EnumerateDefine) {
        /*
         * 左大括号
         * */
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        /*
         * 解析 enum 中的 所有 func
         * */
        let mut status = Status::Continue;
        loop {
            match self.enum_block(define) {
                Status::End => {
                    break;
                },
                Status::Continue => {
                }
            }
        }
    }

    fn enum_block(&mut self, define: &mut EnumerateDefine) -> Status {
        let tp = self.skip_white_space_token();
        match tp {
            Some(p) => {
                return self.enum_block_select(&p, define);
            },
            None => {
                return Status::End;
            }
        }
    }

    fn enum_block_select(&mut self, tp: &TokenPointer, define: &mut EnumerateDefine) -> Status {
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Id => {
                return self.enum_block_item(define);
            },
            TokenType::Annotate => {
                return Status::Continue;
            },
            TokenType::RightBigParenthese => {
                self.skip_next_one();
                return Status::End;
            },
            _ => {
                self.panic(&format!("expect id, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
    }

    fn enum_block_item(&mut self, define: &mut EnumerateDefine) -> Status {
        /*
         * 跳过id token
         * */
        let item_name_token = self.take_next_one().token_value().token_data_unchecked();
        let item_name = extract_token_data!(item_name_token, Id);
        /*
         * 判断后面是否是 括号
         * */
        let tp = self.skip_white_space_token();
        let tp = match tp {
            Some(p) => {
                p
            },
            None => {
                self.panic("expect id, but arrive EOF");
                panic!();
            }
        };
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::LeftParenthese => {
                /*
                 * 直到找到 RightParenthese
                 * */
                let context = EnumDefineItemContext::new_with_all(item_name, None);
                self.enum_block_item_content(context, define);
            },
            _ => {
                self.panic(&format!("expect id, but meet {:?}", token.context_token_type()));
                panic!();
            }
        }
        Status::Continue
    }

    fn enum_block_item_content(&mut self, mut context: EnumDefineItemContext
                               , define: &mut EnumerateDefine) {
        let format_define = self.format_define(TokenType::RightParenthese);
        context.format = Some(format_define);
        check_desc_result!(self, self.cb().enum_define_item(context, define));
    }
}

