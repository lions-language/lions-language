use crate::grammar::{GrammarParser, Grammar, TypeToken};
use crate::lexical::{CallbackReturnStatus, TokenVecItem
    , TokenPointer};
use crate::token::{TokenType, TokenData};
use libtype::{Type, TypeValue, TypeAttrubute, Primeval, Structure};
use libtype::function::{FunctionParamLengthenAttr};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    fn typ_startwith_id(&mut self) -> TypeToken {
        /*
         * take id token
         * */
        let token = self.take_next_one();
        /*
         * id 后面可能是 :: / . / ...
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                return TypeToken::Single(token.token_value());
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::Point => {
                unimplemented!();
            },
            TokenType::ColonColon => {
                unimplemented!();
            },
            _ => {
                return TypeToken::Single(token.token_value());
            }
        }
    }

    fn typ_startwith_parenthese(&mut self) -> TypeToken {
        unimplemented!();
    }

    pub fn typ_parse(&mut self)
        -> (TypeAttrubute, FunctionParamLengthenAttr, TypeToken) {
        let tp = self.expect_next_token(|_, _| {
        }, "id / & / * / ...");
        self._typ_parse(&mut FunctionParamLengthenAttr::Fixed
            , tp.expect("should not happend"))
    }

    pub fn typ_parse_with_next(&mut self, t: TokenPointer)
        -> (TypeAttrubute, FunctionParamLengthenAttr, TypeToken) {
        self._typ_parse(&mut FunctionParamLengthenAttr::Fixed
            , t)
    }

    fn _typ_parse(&mut self, lengthen_attr: &mut FunctionParamLengthenAttr
        , tp: TokenPointer)
        -> (TypeAttrubute, FunctionParamLengthenAttr, TypeToken) {
        /*
         * 解析类型表达式
         * */
        let mut typ_attr = TypeAttrubute::default();
        // let mut lengthen_attr = FunctionParamLengthenAttr::Fixed;
        let token = tp.as_ref::<T, CB>();
        match token.context_token_type() {
            TokenType::Id => {
                typ_attr = TypeAttrubute::Move;
            },
            TokenType::Multiplication => {
                typ_attr = TypeAttrubute::Pointer;
                self.skip_next_one();
            },
            TokenType::ThreePoint => {
                *lengthen_attr = FunctionParamLengthenAttr::Lengthen;
                self.skip_next_one();
                let tp = self.expect_next_token(|_, _| {
                }, "expect id / `*` / `&`").expect("should not happend");
                return self._typ_parse(lengthen_attr, tp);
            },
            TokenType::And => {
                typ_attr = TypeAttrubute::Ref;
                self.skip_next_one();
            }
            _ => {
                self.panic(
                    &format!("expect id / `*` / `&`, but meet {:?}"
                        , token.context_token_type()));
            }
        }
        /*
         * 判断后面是不是 合理的类型token
         * */
        let tp = self.expect_next_token(|_, _| {
        }, "id");
        let token = tp.expect("should not happend").as_ref::<T, CB>();
        let type_token = match token.context_token_type() {
            TokenType::Id => {
                self.typ_startwith_id()
            },
            TokenType::LeftParenthese => {
                self.typ_startwith_parenthese()
            },
            _ => {
                panic!("should not happend: {:?}", token.context_token_type());
            }
        };
        (typ_attr, lengthen_attr.clone(), type_token)
    }
}
