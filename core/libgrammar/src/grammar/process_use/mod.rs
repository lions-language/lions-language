use libresult::{DescResult};
use super::{GrammarParser, Grammar
    , UseStmtContext};
use crate::token::{TokenData};
use crate::lexical::{CallbackReturnStatus};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn use_process(&mut self) {
        /*
         * 跳过 use 关键字
         * */
        self.skip_next_one();
        let mut content = String::new();
        self.parse_use_content(&mut content);
        check_desc_result!(self, self.cb().use_stmt(
            UseStmtContext::new_with_all(content)));
    }

    fn parse_use_content(&mut self, content: &mut String) {
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
