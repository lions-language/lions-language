use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use libhosttype::primeval::{PrimevalControl, PrimevalMethod};
use libhosttype::primeval::finder_map::hash;
use libtype::{Type, primeval::PrimevalType, Primeval};
use libtype::function::splice::FunctionSplice;
use libtype::function::{FunctionParamData, FunctionReturnData
        , FunctionParamDataItem, FunctionReturnDataItem
        , FindFunctionContext, FindFunctionResult};
use libtypecontrol::function::FunctionControl;
use libresult::*;

pub struct Compile {
    function_control: FunctionControl,
    value_buffer: value_buffer::ValueBuffer,
    module_stack: module_stack::ModuleStack
}

impl Grammar for Compile {
    fn express_const_number(&mut self, value: TokenValue) {
        let tt = value.token_type();
        let t = self.tokentype_to_type(tt);
        self.value_buffer.push(t);
    }

    fn operator_plus(&mut self, value: TokenValue) -> NullResult {
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
        let statement_str = FunctionSplice::get_function_without_return_string_by_type(
            "+", &Some(&param), &Some(&typ));
        /*
         * 查找方法声明
         * */
        match self.function_control.find_function(&FindFunctionContext{
            typ: &typ,
            func_str: &statement_str,
            module_str: self.module_stack.current().to_str()
        }) {
            FindFunctionResult::Success(_) => {
            },
            FindFunctionResult::Panic(desc) => {
                return Err(desc);
            }
        }
        NULLOK
        /*
        let left_type_str = self.tokenvalue_type_str(left);
        let right = self.value_buffer.top_n_with_panic(1);
        let right_type_str = self.tokenvalue_type_str(right);
        let func_key = self.splice_binary_operator_funckey(
            left_type_str, "+", right_type_str);
        let current_module = self.module_stack.current();
        */
        // self.primeval_control
    }
}

mod module_stack;
mod value_buffer;
mod aide;
