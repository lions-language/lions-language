use libtype::structure::{StructDefine};
use super::{GrammarParser, Grammar
    , StructDefineContext};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenValue, TokenData};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn structure_process(&mut self) {
        /*
         * 跳过 struct 关键字
         * */
        self.skip_next_one();
        /*
         * 匹配 id (结构体名称)
         * */
        let name_token = self.expect_and_take_next_token_unchecked(TokenType::Id);
        let name = extract_token_data!(name_token.token_value().token_data_unchecked(), Id);
        let mut define = StructDefine::new_with_all(
            name, None);
        self.cb().struct_define_start(&mut define);
        let mut define_context = StructDefineContext::default();
        self.struct_parse_field_list(&mut define_context, &mut define);
        self.cb().struct_define_end(define);
    }
}

mod field;
 
