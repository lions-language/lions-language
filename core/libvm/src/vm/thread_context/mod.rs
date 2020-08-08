use libtype::{Data, AddressValue
    , AddressKey};
use libmacro::{FieldGet};
use libcommon::ptr::RefPtr;
use scope::context::{ScopeContext};
use crate::memory::stack::RandStack;

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
        let scope = addr.scope_clone();
        self.scope_context.last_n_unchecked(scope).get_data_unchecked(
            addr, link_static, &self.memory)
        /*
        self.scope_context.current_unchecked().get_data_unchecked(
            addr, link_static, &self.memory)
        */
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

    /*
    /*
     * last n
     * */
    pub fn get_last_n_data_unchecked(&self, addr: &AddressValue, n: usize
        , link_static: &RefPtr)
        -> RefPtr {
        self.scope_context.last_n_unchecked(n).get_data_unchecked(
            addr, link_static, &self.memory)
    }

    pub fn alloc_and_write_last_n_data(&mut self, addr: &AddressValue
        , n: usize, data: Data) {
        let memory = RefPtr::from_ref::<ThreadMemory>(&self.memory);
        self.scope_context.last_n_mut_unchecked(n).alloc_and_write_data(
            addr, data, memory);
    }

    pub fn alloc_and_write_last_n_static(&mut self, addr: &AddressValue
        , n: usize, static_addr: AddressKey) {
        self.scope_context.last_n_mut_unchecked(n).alloc_and_write_static(
            addr, static_addr);
    }

    pub fn alloc_and_write_last_one_data(&mut self, addr: &AddressValue
        , data: Data) {
        self.alloc_and_write_last_n_data(addr, 1, data);
    }

    /*
     * lats one
     * */
    pub fn get_last_one_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr)
        -> RefPtr {
        self.get_last_n_data_unchecked(addr, 1, link_static)
    }

    pub fn alloc_and_write_last_one_static(&mut self, addr: &AddressValue
        , static_addr: AddressKey) {
        self.alloc_and_write_last_n_static(addr, 1, static_addr);
    }
    */

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
