use crate::lexical::{CallbackReturnStatus, LexicalParser};
use crate::grammar::{Grammar};
use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    fn point(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Point);
        self.push_to_token_buffer(point::PointToken::new(context));
    }

    fn point_two(&mut self) {
        /*
         * 跳过 .
         * */
        self.content.skip_next_one();
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                '.' => {
                    /*
                     * ...
                     * */
                    parser.point_three();
                },
                _ => {
                    /*
                     * ..
                     * */
                    let context = parser.build_token_context_without_data(TokenType::TwoPoint);
                    parser.push_to_token_buffer(two_point::TwoPointToken::new(context));
                }
            }
        }, |parser| {
        });
    }

    fn point_three(&mut self) {
        let context = self.build_token_context_without_data(TokenType::ThreePoint);
        self.push_to_token_buffer(three_point::ThreePointToken::new(context));
    }

    pub fn point_process(&mut self) {
        /*
         * 跳过 .
         * */
        self.content.skip_next_one();
        self.lookup_next_one_with_cb_wrap(|parser, c| {
            match c {
                '.' => {
                    parser.point_two();
                },
                _ => {
                    /*
                     * .
                     * */
                    parser.point();
                }
            }
        }, |parser| {
        });
    }
}
            
pub mod point;
pub mod two_point;
pub mod three_point;
