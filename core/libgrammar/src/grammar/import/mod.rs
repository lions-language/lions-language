use super::{LexicalParser};
use libresult::{DescResult};
use libcommon::strtool::strcompare::{U8ArrayIsEqual
    , U8ArrayIsEqualResult};
use libcommon::ptr::{RefPtr};
use libcommon::consts;
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , ReturnStmtContext, ImportStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn import_process(&mut self) {
        /*
         * 跳过 import 关键字
         * */
        self.skip_next_one();
        match self.lexical_parser.lookup_next_one_not_spacewhite_in_this_line() {
            Some(c) => {
                match c {
                    '"' => {
                        self.parse_import_stmt();
                    },
                    '(' => {
                        unimplemented!();
                    },
                    _ => {
                        self.panic(&format!("expect \" / (, but meet {}", c));
                    }
                }
            },
            None => {
                self.panic("expect \", but arrive IOEof");
            }
        }
    }

    fn import_as(&mut self) -> Option<String> {
        /*
         * 查看是否有 as 存在
         * */
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => tp,
            None => {
                /*
                 * import "" 后面是文件结尾 => 语法正确, 不需要处理
                 * */
                return None;
            }
        };
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::As => {
                self.skip_next_one();
                self.expect_next_token(|grammar, tp| {
                    let token = tp.as_ref::<T, CB>();
                    match token.context_token_type() {
                        TokenType::Id => {
                        },
                        _ => {
                            grammar.panic(
                                &format!("expect id after module, but meet {:?}"
                                    , token.context_token_type()));
                        }
                    }
                }, "id after module");
                let t = self.take_next_one();
                let alias = extract_token_data!(
                    t.token_value().token_data().expect("should not happend")
                    , Id);
                Some(alias)
            },
            _ => {
                None
            }
        }
    }

    fn import_prefix_match(&mut self, local_obj: &mut U8ArrayIsEqual
        , import_prefix: consts::ImportPrefixType
        , parser: &mut LexicalParser<T, CB>, c: char, is: &mut bool
        , content: &mut String) -> bool {
        match local_obj.dynamic_match(c) {
            U8ArrayIsEqualResult::Match(_) => {
                parser.content_skip_next_one();
                parser.lookup_next_one_with_cb_wrap(|parser, c| {
                    if c == ':' {
                        /*
                         * 跳过 : 号
                         * import "local:xxx" 形式
                         * */
                        parser.content_skip_next_one();
                    }
                }, |parser| {
                    parser.panic("expect match \", but arrive IOEof");
                });
                /*
                 * 解析 local: 后面的 字符串 (遇到 " 结束)
                 * */
                self.parse_import_content(content);
                *is = false;
                let alias = self.import_as();
                check_desc_result!(self, self.cb().import_stmt(ImportStmtContext::new(
                        import_prefix, content)));
                return true;
            },
            _ => {
            }
        }
        false
    }

    fn parse_import_stmt(&mut self) {
        /*
         * 跳过 "
         * */
        self.lexical_parser.content_skip_next_one();
        let mut is = true;
        let mut local_obj = U8ArrayIsEqual::new(consts::IMPORT_LOCAL.as_bytes());
        let mut packages_obj = U8ArrayIsEqual::new(consts::IMPORT_PACKAGE.as_bytes());
        let mut system_obj = U8ArrayIsEqual::new(consts::IMPORT_SYSTEM.as_bytes());
        let mut grammar_ptr = RefPtr::from_ref(self);
        let mut content = String::new();
        let mut no_prefix = String::new();
        while is {
            self.lexical_parser.lookup_next_one_with_cb_wrap(|parser, c| {
                match c {
                    '"' => {
                        /*
                         * import "xxx" 形式, 相当于是 import "local:xxx"
                         * */
                        is = false;
                        parser.content_skip_next_one();
                        let grammar = grammar_ptr.as_mut::<GrammarParser<T, CB>>();
                        let alias = grammar.import_as();
                        check_desc_result!(grammar, grammar.cb().import_stmt(ImportStmtContext::new(
                                consts::ImportPrefixType::Local, &no_prefix)));
                    },
                    _ => {
                        let grammar = grammar_ptr.as_mut::<GrammarParser<T, CB>>();
                        if_true_return!(grammar.import_prefix_match(&mut local_obj
                                , consts::ImportPrefixType::Local, parser, c, &mut is, &mut content));
                        if_true_return!(grammar.import_prefix_match(&mut packages_obj
                                , consts::ImportPrefixType::Package, parser, c, &mut is, &mut content));
                        if_true_return!(grammar.import_prefix_match(&mut system_obj
                                , consts::ImportPrefixType::System, parser, c, &mut is, &mut content));
                        parser.content_skip_next_one();
                        no_prefix.push(c);
                    }
                }
            }, |parser| {
                parser.panic("expect match \", but arrive IOEof");
            });
        }
    }

    fn parse_import_content(&mut self, content: &mut String) {
        let mut is = true;
        while is {
            self.lexical_parser.lookup_next_one_with_cb_wrap(|parser, c| {
                match c {
                    '"' => {
                        is = false;
                        parser.content_skip_next_one();
                    },
                    _ => {
                        content.push(c);
                        parser.content_skip_next_one();
                    }
                }
            }, |parser| {
                parser.panic("expect match \", but arrive IOEof");
            });
        }
    }
}
