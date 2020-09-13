use libtype::{Data, AddressValue
    , AddressKey, AddressType};
use libmacro::{FieldGet};
use libcommon::ptr::RefPtr;
use scope::context::{ScopeContext};
use crate::memory::stack::rand::RandStack;
use crate::memory::{Rand, MemoryValue};

#[derive(FieldGet)]
pub struct ThreadMemory {
    stack_data: RandStack<Data>,
}

impl ThreadMemory {
    pub fn new() -> Self {
        Self {
            stack_data: RandStack::<Data>::new()
        }
    }
}

#[derive(FieldGet)]
pub struct ThreadScope {
    scope_context: ScopeContext,
    memory: ThreadMemory
}

impl ThreadScope {
    pub fn get_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr)
        -> RefPtr {
        /*
         * 获取作用域
         * */
        self.scope_context.get_data_unchecked(
            addr, link_static, &self.memory)
        /*
        self.scope_context.current_unchecked().get_data_unchecked(
            addr, link_static, &self.memory)
        */
    }

    pub fn get_data_by_data_addr_unchecked(&self
        , data_addr: &MemoryValue
        , link_static: &RefPtr)
        -> RefPtr {
        let scope = data_addr.addr_value_ref().addr_ref().scope_clone();
        // println!("{}", scope);
        // self.print_stack_datas();
        self.scope_context.last_n_unchecked(scope).get_data_by_data_addr_unchecked(
            data_addr, link_static, &self.memory)
    }

    pub fn take_data_unchecked(&mut self, addr: &AddressValue
        , link_static: &RefPtr)
        -> Data {
        // self.print_addr_mapping(addr.addr_clone());
        // self.print_stack_datas();
        let scope = addr.scope_clone();
        self.scope_context.last_n_mut_unchecked(scope).take_data_unchecked(
            addr, link_static, &mut self.memory)
    }

    pub fn get_data_addr_unchecked(&self, addr: &AddressKey) -> &MemoryValue {
        let scope = addr.scope_clone();
        // println!("{}", scope);
        self.scope_context.last_n_unchecked(scope).get_data_addr_unchecked(addr)
    }

    pub fn alloc_and_write_data(&mut self, addr: &AddressValue
        , data: Data) {
        let memory = RefPtr::from_ref::<ThreadMemory>(&self.memory);
        let scope = addr.scope_clone();
        self.scope_context.last_n_mut_unchecked(scope).alloc_and_write_data(
            addr, data, memory);
        /*
        self.scope_context.current_mut_unchecked().alloc_and_write_data(
            addr, data, memory);
        */
    }

    pub fn alloc_and_write_static(&mut self, addr: &AddressValue
        , static_addr: AddressKey) {
        let scope = addr.scope_clone();
        self.scope_context.last_n_mut_unchecked(scope).alloc_and_write_static(
            addr, static_addr);
        /*
        self.scope_context.current_mut_unchecked().alloc_and_write_static(
            addr, static_addr);
        */
    }

    pub fn add_bind(&mut self, addr: AddressKey
        , src_addr: AddressValue) {
        let scope = addr.scope_clone();
        self.scope_context.last_n_mut_unchecked(scope).add_bind(
            addr, src_addr);
    }

    pub fn add_ref_param_addr_bind(&mut self, addr: AddressKey
        , src_addr: AddressValue) {
        let scope = addr.scope_clone();
        self.scope_context.last_n_mut_unchecked(scope).add_ref_param_addr_bind(
            addr, src_addr);
    }

    pub fn remove_bind(&mut self, addr: AddressKey) {
        let scope = addr.scope_clone();
        self.scope_context.last_n_mut_unchecked(scope).remove_bind(addr);
    }

    pub fn set_result_data_addr(&mut self, scope: usize
        , addr_value: AddressValue) {
        self.scope_context.last_n_mut_unchecked(scope).set_result_data_addr(addr_value);
    }

    pub fn get_result_data_addr(&self) -> &AddressValue {
        self.scope_context.current_unchecked().get_result_data_addr()
    }

    pub fn leave_scope_last_n(&mut self, n: usize) {
        self.scope_context.leave_last_n(n);
    }
    
    pub fn print_current_addr_mapping(&self) {
        println!("**************** current scope addr mapping ******************");
        self.scope_context.last_n_unchecked(0).print_addr_mapping();
        println!("*************************************************************");
    }

    pub fn print_last_n_addr_mapping(&self, scope: usize) {
        if !self.scope_context.last_n_is_valid(scope) {
            return;
        }
        println!("**************** last {} scope addr mapping ******************", scope);
        self.scope_context.last_n_unchecked(scope).print_addr_mapping();
        println!("**************************************************************");
    }

    pub fn print_addr_mapping(&mut self, addr: AddressKey) {
        let scope = addr.scope_clone();
        println!("**************** scope: {} addr mapping ******************", scope);
        self.scope_context.last_n_mut_unchecked(scope).print_addr_mapping();
        println!("**********************************************************");
    }

    pub fn print_stack_datas(&self) {
        println!("**************** stack data ******************");
        self.memory.stack_data.print_datas();
        println!("**********************************************");
    }

    pub fn print_recycles(&self) {
        println!("**************** recycles ******************");
        self.memory.stack_data.print_recycles();
        println!("********************************************");
    }

    pub fn new() -> Self {
        Self {
            scope_context: ScopeContext::new(),
            memory: ThreadMemory::new()
        }
    }
}

pub mod context;
pub mod scope;
