use libresult::{DescResult};
use libcommon::strtool::strcompare::{U8ArrayIsEqual
    , U8ArrayIsEqualResult};
use libcommon::ptr::{RefPtr};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , ReturnStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

const LOCAL: &'static str = "local";
const PATH: &'static str = "path";
const PACKAGES: &'static str = "packages";
const SYSTEM: &'static str = "system";

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

    fn parse_import_stmt(&mut self) {
        /*
         * 跳过 "
         * */
        self.lexical_parser.content_skip_next_one();
        let mut is = true;
        let mut local_obj = U8ArrayIsEqual::new(LOCAL.as_bytes());
        let mut grammar_ptr = RefPtr::from_ref(self);
        while is {
            self.lexical_parser.lookup_next_one_with_cb_wrap(|parser, c| {
                match c {
                    '"' => {
                        /*
                         * import "xxx" 形式, 相当于是 import "local:xxx"
                         * */
                        is = false;
                        parser.content_skip_next_one();
                    },
                    _ => {
                        match local_obj.dynamic_match(c) {
                            U8ArrayIsEqualResult::Match(size) => {
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
                                let grammar = grammar_ptr.as_mut::<GrammarParser<T, CB>>();
                                grammar.parse_import_content();
                                is = false;
                                return;
                            },
                            _ => {
                            }
                        }
                        parser.content_skip_next_one();
                    }
                }
            }, |parser| {
                parser.panic("expect match \", but arrive IOEof");
            });
        }
    }

    fn parse_import_content(&mut self) {
        let mut is = true;
        let mut path = String::new();
        while is {
            self.lexical_parser.lookup_next_one_with_cb_wrap(|parser, c| {
                match c {
                    '"' => {
                        is = false;
                        parser.content_skip_next_one();
                    },
                    _ => {
                        path.push(c);
                        parser.content_skip_next_one();
                    }
                }
            }, |parser| {
                parser.panic("expect match \", but arrive IOEof");
            });
        }
        panic!("{}", path);
    }
}
