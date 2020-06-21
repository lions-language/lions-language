use crate::lexical::{LexicalParser, CallbackReturnStatus};
use libcommon::strtool::strcompare::{U8ArrayIsEqual, U8ArrayIsEqualResult};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    /*
     * 匹配字符串
     * 1. 如果匹配到了输入的字符串, 就返回 true
     * 2. 如果找不到匹配的输入字符串, 回溯到原来的位置, 并返回 false
     * */
    pub fn input_str_match(&mut self, src: &[u8]) -> bool {
        let mut tool = U8ArrayIsEqual::new(src);
        self.input_str_match_with_u8arrayisequal(&mut tool)
    }

    pub fn input_str_match_with_u8arrayisequal<'a>(&mut self, tool: &mut U8ArrayIsEqual<'a>) -> bool {
        type Result = U8ArrayIsEqualResult;
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    match tool.dynamic_match(c) {
                        Result::NoMatch(length) => {
                            self.content.backtrack_n(length);
                            tool.reset();
                            return false;
                        },
                        Result::Continue => {
                            self.content.virtual_skip_next_one();
                            continue;
                        },
                        Result::Match(length) => {
                            self.content.skip_next_n(length);
                            tool.reset();
                            return true;
                        }
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            self.content_assign(content);
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            tool.reset();
                            return false;
                        }
                    }
                }
            }
        }
    }
}
