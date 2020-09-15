use libcommon::ptr::RefPtr;
use libtype::function::{FunctionDefine, Function
    , FunctionParamDataItem
    , FunctionReturn
    , FunctionReturnDataAttr};
use libtype::instruction::{Instruction, CallPrimevalFunction
    , CallFunction, StaticVariant
    , LoadStack, OwnershipMove
    , AddressBind, ReturnStmt
    , Jump, RemoveOwnership
    , AddRefParamAddr};
use crate::compile::{StaticContext, CallFunctionContext
    , FunctionNamedStmtContext, Compile
    , LoadStackContext, OwnershipMoveContext
    , AddressBindContext, ReturnStmtContext};
use define_stack::DefineStack;
use crate::define_dispatch::{FunctionDefineDispatch};

pub trait Writer {
    fn write(&mut self, _: Instruction) {
    }
    fn current_index(&self) -> usize {
        unimplemented!();
    }
    fn set_jump(&mut self, _: usize, _: Jump) {
        unimplemented!();
    }
}

pub struct Bytecode<'a, 'b, F: Writer> {
    writer: &'a mut F,
    define_stack: DefineStack,
    func_define_dispatch: &'a mut FunctionDefineDispatch<'b>
}

impl<'a, 'b, F: Writer> Compile for Bytecode<'a, 'b, F> {
    fn const_number(&mut self, context: StaticContext) {
        let instruction = Instruction::ReadStaticVariant(StaticVariant{
            package_str: context.package_str,
            addr: context.addr,
            static_addr: context.static_addr
        });
        self.write(instruction);
    }

    fn const_string(&mut self, context: StaticContext) {
        let instruction = Instruction::ReadStaticVariant(StaticVariant{
            package_str: context.package_str,
            addr: context.addr,
            static_addr: context.static_addr
        });
        self.write(instruction);
    }
    
    fn load_stack(&mut self, context: LoadStackContext) {
        let (addr, data) = context.fields_move();
        // println!("{:?}", addr);
        self.write(Instruction::LoadStack(LoadStack::new_with_all(
                    addr, data)));
    }

    fn call_function(&mut self, context: CallFunctionContext) {
        match &context.func.func_define {
            FunctionDefine::Optcode(def) => {
                let instruction = Instruction::CallPrimevalFunction(
                    CallPrimevalFunction{
                        opt: def.optcode.clone(),
                        param_addrs: context.param_addrs,
                        call_param_len: context.call_param_len,
                        return_data: context.return_data
                    }
                    );
                self.write(instruction);
            },
            FunctionDefine::Address(addr) => {
                let instruction = Instruction::CallFunction(
                    CallFunction{
                        package_str: context.package_str,
                        define_addr: addr.addr_ref().clone(),
                        return_data: context.return_data
                    }
                );
                self.write(instruction);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn function_define_start(&mut self) {
    }

    fn function_named_stmt(&mut self, context: FunctionNamedStmtContext) -> RefPtr {
        let (statement_ptr, define_obj) = self.func_define_dispatch.alloc_define(context);
        self.define_stack.enter(define_obj);
        statement_ptr
    }

    fn function_push_param_to_statement(&mut self
        , item: FunctionParamDataItem) {
        let ds = self.define_stack.back_mut_unchecked();
        self.func_define_dispatch.push_function_param_to_statement(ds, item);
    }

    fn function_set_return_to_statement(&mut self
        , item: FunctionReturn) {
        let ds = self.define_stack.back_mut_unchecked();
        self.func_define_dispatch.set_function_return_to_statement(ds, item);
    }

    fn update_func_return_data_addr(&mut self, attr: FunctionReturnDataAttr) {
        let ds = self.define_stack.back_mut_unchecked();
        self.func_define_dispatch.update_func_return_data_attr(ds, attr);
    }

    fn function_define_end(&mut self) -> Function {
        let ds = self.define_stack.leave();
        self.func_define_dispatch.finish_define(&ds)
    }

    fn ownership_move(&mut self, context: OwnershipMoveContext) {
        // println!("{:?}", &context);
        // println!("ownership move");
        let (dst_addr, src_addr) = context.fields_move();
        self.write(Instruction::OwnershipMove(OwnershipMove::new_with_all(
                    dst_addr, src_addr)));
    }

    fn address_bind(&mut self, context: AddressBindContext) {
        let (src_addr, dst_addr) = context.fields_move();
        self.write(Instruction::AddressBind(AddressBind::new_with_all(
            src_addr, dst_addr.addr())));
    }

    fn return_stmt(&mut self, context: ReturnStmtContext) {
        let (scope, addr_value) = context.fields_move();
        self.write(Instruction::ReturnStmt(ReturnStmt::new_with_all(
                    scope, addr_value)));
    }

    fn jump(&mut self, context: Jump) -> usize {
        self.write(Instruction::Jump(context));
        self.current_index()
    }

    fn current_index(&self) -> usize {
        if self.define_stack.is_empty() {
            self.writer.current_index()
        } else {
            self.define_stack.current_index()
        }
    }

    fn set_jump(&mut self, index: usize, jump: Jump) {
        if self.define_stack.is_empty() {
            self.writer.set_jump(index, jump);
        } else {
            self.define_stack.set_jump(index, jump);
        }
    }

    fn enter_scope(&mut self) {
        // println!("xxxxxxx");
        self.write(Instruction::EnterScope);
    }

    fn leave_scope(&mut self) {
        // println!("yyyyyyyyy");
        self.write(Instruction::LeaveScope);
    }

    fn remove_ownership(&mut self, context: RemoveOwnership) {
        self.write(Instruction::RemoveOwnership(context));
    }

    fn add_ref_param_addr(&mut self, context: AddRefParamAddr) {
        self.write(Instruction::AddRefParamAddr(context));
    }
}

impl<'a, 'b, F: Writer> Bytecode<'a, 'b, F> {
    fn write(&mut self, instruction: Instruction) {
        /*
         * NOTE: 决定将字节码向哪个输出流写
         * */
        if self.define_stack.is_empty() {
            self.writer.write(instruction);
        } else {
            self.define_stack.write(instruction);
        }
    }

    pub fn new(writer: &'a mut F, func_define_dispatch: &'a mut FunctionDefineDispatch<'b>) -> Self {
        Self {
            writer: writer,
            define_stack: DefineStack::new(),
            func_define_dispatch: func_define_dispatch
        }
    }
}

mod define_stack;

#[cfg(test)]
mod test {
    use libgrammar::lexical::VecU8;
    use libgrammar::lexical::LexicalParser;
    use libgrammar::grammar::GrammarParser;
    use libgrammar::lexical::CallbackReturnStatus;
    use libgrammar::grammar::GrammarContext;
    use libtype::module::Module;
    use crate::compile::{Compiler, InputContext, InputAttribute, FileType};
    use crate::address::{PackageIndex};
    use crate::define_stream::DefineStream;
    use crate::static_dispatch::{StaticVariantDispatch};
    use crate::static_stream::{StaticStream};
    use super::*;

    use std::fs;
    use std::io::Read;

    struct TestWriter {
    }

    impl Writer for TestWriter {
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
        let mut ds = DefineStream::new();
        let mut fdd = FunctionDefineDispatch::new(&mut ds);
        let mut static_stream = StaticStream::new();
        let mut static_variant_dispatch = StaticVariantDispatch::new(&mut static_stream);
        let mut package_index = PackageIndex::new();
        let package_str = String::from("test");
        let mut test_writer = TestWriter{};
        let mut grammar_context = GrammarContext{
            cb: Compiler::new(
                Module::new(String::from("main")),
                Bytecode::new(
                    &mut test_writer
                    , &mut fdd),
                InputContext::new(InputAttribute::new(FileType::Main)),
                &mut package_index,
                &mut static_variant_dispatch,
                &package_str
            )
        };
        let mut grammar_parser = GrammarParser::new(lexical_parser, &mut grammar_context);
        grammar_parser.parser();
    }
}
