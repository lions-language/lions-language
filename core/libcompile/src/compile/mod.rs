use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libtype::function::splice::FunctionSplice;
use libtype::function::{FunctionParamData
        , FunctionParamDataItem
        , FindFunctionContext, FindFunctionResult};
use libtypecontrol::function::FunctionControl;
use libtype::primeval::{PrimevalType, PrimevalData};
use libtype::module::Module;
use libresult::*;

#[derive(Debug)]
pub struct ConstContext {
    pub typ: PrimevalType,
    pub data: PrimevalData
}

pub trait Compile {
    fn const_number(&mut self, context: ConstContext) {
        println!("{:?}", context);
    }
}

pub struct Compiler<F: Compile> {
    function_control: FunctionControl,
    value_buffer: value_buffer::ValueBuffer,
    module_stack: module_stack::ModuleStack,
    cb: F
}

impl<F: Compile> Grammar for Compiler<F> {
    fn const_number(&mut self, value: TokenValue) {
        let tt = value.token_type_clone();
        let t = self.tokentype_to_type(tt);
        self.value_buffer.push(t);
        let const_context = ConstContext::from_token_value(value);
        self.cb.const_number(const_context);
    }

    fn operator_plus(&mut self, _value: TokenValue) -> DescResult {
        use libtype::function::consts;
        /*
         * 取出前两个token, 查找第一个函数的 plus 方法
         * */
        let right = self.value_buffer.take_top();
        let left = self.value_buffer.take_top();
        /*
         * 构建方法所属类型 => left 类型
         * */
        let typ = left;
        /*
         * 构建 函数参数
         * + 号运算一定只有一个参数
         * */
        let param = FunctionParamData::Single(FunctionParamDataItem::new(right));
        let statement_str = FunctionSplice::get_function_without_return_and_type_string(
            consts::OPERATOR_FUNCTION_NAME, &Some(&param));
        /*
         * 查找方法声明
         * */
        match self.function_control.find_function(&FindFunctionContext{
            typ: &typ,
            func_str: &statement_str,
            module_str: self.module_stack.current().to_str()
        }) {
            FindFunctionResult::Success(r) => {
                /*
                 * 获取返回类型, 如果存在返回类型, 将其写入到队列中
                 * */
                match &r.func.func_statement.func_return {
                    Some(ret) => {
                        /*
                         * 存在返回值
                         * */
                        self.value_buffer.push(ret.data.typ.clone());
                    },
                    None => {
                    }
                }
            },
            FindFunctionResult::Panic(desc) => {
                return DescResult::Error(desc);
            }
        }
        DescResult::Success
    }
}

mod module_stack;
mod value_buffer;
mod aide;
mod context;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use super::*;

    use std::fs;
    use std::io::Read;

    struct TestComplie {
    }

    impl Compile for TestComplie {
    }

    #[test]
    fn grammar_parser_test() {
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
        let mut grammar_context = GrammarContext{
            cb: Compiler{
                function_control: FunctionControl::new(),
                value_buffer: value_buffer::ValueBuffer::new(),
                module_stack: module_stack::ModuleStack::new(
                    Module::new(String::from("main"))),
                cb: TestComplie{}
            }
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
