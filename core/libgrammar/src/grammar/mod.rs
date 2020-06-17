use crate::lexical::{LexicalParser, CallbackReturnStatus};

pub struct GrammarParser<FT: FnMut() -> CallbackReturnStatus> {
    lexical_parser: LexicalParser<FT>
}

impl<FT: FnMut() -> CallbackReturnStatus> GrammarParser<FT> {
    pub fn parser(&mut self) {
    }

    pub fn new(lexical_parser: LexicalParser<FT>) -> Self {
        Self {
            lexical_parser: lexical_parser
        }
    }
}

mod test {
    use super::*;
    use crate::lexical::{VecU8};

    use std::fs;
    use std::io::Read;

    #[test]
    fn grammar_parser_test() {
        let mut file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(err) => {
                panic!("read file error");
            }
        };
        let mut obj = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let mut f_ref = f.by_ref();
            match f_ref.take(1).read_to_end(&mut v) {
                Ok(len) => {
                    if len == 0 {
                        return CallbackReturnStatus::End;
                    } else {
                        return CallbackReturnStatus::Continue(VecU8::from_vec_u8(v));
                    }
                },
                Err(_) => {
                    return CallbackReturnStatus::End;
                }
            }
        });
    }
}

