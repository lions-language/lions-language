use libcompile::bytecode::{self};
use libtype::instruction::{Instruction};
use libcommon::ptr::RefPtr;
use crate::define::{LinkDefine};

pub struct Link {
    link_define: LinkDefine,
    call_main_instruction: Instruction
}

impl bytecode::Writer for Link {
    fn write(&mut self, instruction: Instruction) {
        // println!("{:?}", instruction);
        self.link_define.start(&instruction);
        *&mut self.call_main_instruction = instruction;
    }
}


impl Link {
    pub fn link_define(&mut self) -> &mut LinkDefine {
        &mut self.link_define
    }

    pub fn call_main_instruction(&self) -> &Instruction {
        &self.call_main_instruction
    }

    pub fn new(define_stream: RefPtr) -> Self {
        Self {
            link_define: LinkDefine::new(define_stream),
            call_main_instruction: Instruction::Invalid
        }
    }
}

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use libcompile::compile::{FileType, Compile, Compiler
    , InputAttribute, InputContext};
    use libcompile::address::PackageIndex;
    use libcompile::bytecode::{self, Bytecode};
    use libcompile::define_stream::{DefineStream};
    use libcompile::define_dispatch::{FunctionDefineDispatch};
    use super::*;

    use std::fs;
    use std::io::Read;

    #[test]
    // #[ignore]
    fn link_test() {
        let file = String::from("main.lions");
        let mut f = match fs::File::open(&file) {
            Ok(f) => f,
            Err(_err) => {
                panic!("read file error");
            }
        };
        let lexical_parser = LexicalParser::new(file.clone(), || -> CallbackReturnStatus {
            let mut v = Vec::new();
            let f_ref = f.by_ref();
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
        let mut ds = DefineStream::new();
        let ds_ptr = RefPtr::from_ref::<DefineStream>(&ds);
        let mut fdd = FunctionDefineDispatch::new(&mut ds);
        let mut package_index = PackageIndex::new();
        let package_str = String::from("test");
        let mut link = Link::new(ds_ptr);
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(
                    Module::new(String::from("main"))
                    , Bytecode::new(
                        &mut link
                        , &mut fdd)
                    , InputContext::new(InputAttribute::new(
                            FileType::Main))
                    , &mut package_index
                    , &package_str)
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
