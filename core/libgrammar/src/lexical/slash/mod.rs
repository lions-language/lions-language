use super::{LexicalParser, CallbackReturnStatus};
use libcommon::strtool::strcompare::{U8ArrayIsEqual};
use crate::token::{TokenType};
use division::DivisionToken;
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn slash_process(&mut self) {
        /*
         * 跳过 /
         * */
        self.content.skip_next_one();
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                '/' => {
                    // 单行注释
                    parser.slash_single_annotate();
                },
                '*' => {
                    // 多行注释
                    parser.slash_multi_annotate();
                },
                _ => {
                    // 除法运算符
                    parser.slash_division();
                }
            }
        }, |parser| {
            parser.slash_division();
        });
    }

    fn slash_single_annotate(&mut self) {
        /*
         * 跳过 /
         * */
        self.content.skip_next_one();
        /*
         * 循环查找, 直到遇到新行
         * */
        let mut content = Vec::new();
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    if self.new_line_check(c) {
                        /*
                         * 因为 遇到 \r \n 的时候, self.lines 就会加1, 所以对于单行注释,
                         * 不需要再加1
                         * */
                        self.line -= 1;
                        break;
                    } else {
                        content.push(c as u8);
                        self.content.skip_next_one();
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            self.content_assign(content);
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            break;
                        }
                    }
                }
            }
        }
        self.push_token_annotate(content);
    }

    fn slash_multi_annotate(&mut self) {
        /*
         * 跳过 *
         * */
        self.content.skip_next_one();
        /*
         * 循环查找, 直到遇到 * / 为止
         * */
        let mut times = 1;
        let mut content = Vec::new();
        let start = "/*".as_bytes();
        let end = "*/".as_bytes();
        let mut start_is_equal = U8ArrayIsEqual::new(start);
        let mut end_is_equal = U8ArrayIsEqual::new(end);
        self.lookup_next_loop_with_cb_wrap(|parser, c| -> bool {
            if parser.input_str_match_with_u8arrayisequal(&mut start_is_equal) {
                // match /*
                times += 1;
                /*
                 * 在注释中遇到了 start => 那么这也是注释内容的一部分
                 * */
                content.extend_from_slice(start);
            } else if parser.input_str_match_with_u8arrayisequal(&mut end_is_equal) {
                // match */
                times -= 1;
                if times == 0 {
                    return true;
                } else {
                    /*
                     * times > 0 说明不是最后一个 终结串, 那么就属于注释内容的一部分
                     * */
                    content.extend_from_slice(end);
                }
            } else {
                // not match
                parser.new_line_check(c);
                content.push(c as u8);
                parser.content.skip_next_one();
            }
            false
        }, |parser| {
            parser.panic("multi annotate must match /* and */, but arrive IO EOF");
        });
        self.push_token_annotate(content);
    }

    fn slash_division(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Division);
        self.push_to_token_buffer(DivisionToken::new(context));
    }
}

mod division;

