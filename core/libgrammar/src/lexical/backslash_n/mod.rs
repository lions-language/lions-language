use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn backslash_n(&mut self) {
        // 跳过 \n 号
        self.content.skip_next_one();
        self.push_nooperate_token_to_token_buffer(TokenType::NewLine);
        self.add_one_line();
        // 因为 不需要关心 \n 后面是什么, 所以不需要再调用回调, 获取后面的源码字节数组
    }
}

