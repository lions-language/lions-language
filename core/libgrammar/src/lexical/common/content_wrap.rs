use super::{LexicalParser, CallbackReturnStatus};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    /*
     * 对存在 cb 的情况下, lookup_next_one 的封装
     * */
    pub fn lookup_next_one_with_cb_wrap<FindF, EndF>(&mut self, mut find_f: FindF, mut end_f: EndF)
        where FindF: FnMut(&mut LexicalParser<T>, char), EndF: FnMut(&mut LexicalParser<T>) {
        match self.content.lookup_next_one() {
            Some(c) => {
                find_f(self, c);
            },
            None => {
                match (self.cb)() {
                    CallbackReturnStatus::Continue(content) => {
                        self.content_assign(content);
                        match self.content.lookup_next_one() {
                            Some(c) => {
                                find_f(self, c);
                            },
                            None => {
                                panic!("should not happend");
                            }
                        }
                    },
                    CallbackReturnStatus::End => {
                        end_f(self);
                    }
                }
            }
        }
    }

    pub fn lookup_next_loop_with_cb_wrap<FindF, EndF>(&mut self, mut find_f: FindF, mut end_f: EndF)
        where FindF: FnMut(&mut LexicalParser<T>, char) -> bool, EndF: FnMut(&mut LexicalParser<T>) {
        loop {
            match self.content.lookup_next_one() {
                Some(c) => {
                    if find_f(self, c) {
                        /*
                         * 如果 find_f 返回 true, 将退出循环
                         * */
                        break;
                    }
                },
                None => {
                    match (self.cb)() {
                        CallbackReturnStatus::Continue(content) => {
                            self.content_assign(content);
                            continue;
                        },
                        CallbackReturnStatus::End => {
                            end_f(self);
                        }
                    }
                }
            }
        }
    }
}

