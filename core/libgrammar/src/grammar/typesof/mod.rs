use crate::grammar::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus, TokenVecItem};
use crate::token::{TokenType};
use libcommon::typesof::{Type};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    fn typesof_calc_startwith_id(&mut self) -> Option<Type> {
        /*
         * 获取第一个 token
         * */
        let first = self.take_next_one();
        /*
         * 查看下一个token是否是 ::
         * */
        Some(Type::Primeval)
    }

    pub fn typesof_calc(&mut self) -> Option<Type> {
        /*
         * 解析类型
         * 类型属性(ptr, const); 类型名称(可能有 模块前缀 ::)
         * 模块的解析需要在 grammar parser 层级做
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect Type token, but arrive IO EOf");
                return None;
            }
        };
        let next_token = tp.as_ref::<T, CB>();
        match &next_token.context_ref().token_type {
            TokenType::Id(_) => {
                /*
                 * type / space1::space2::type
                 * */
                return self.typesof_calc_startwith_id();
            },
            TokenType::Multiplication => {
                /*
                 * 指针
                 * */
                return None;
            },
            _ => {
                return None;
            }
        }
    }
}
