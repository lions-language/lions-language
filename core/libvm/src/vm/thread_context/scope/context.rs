use libtype::{
    AddressValue, AddressType};
use libcommon::ptr::{RefPtr};
use super::{Scope};
use std::collections::VecDeque;
use crate::vm::thread_context::{ThreadMemory};
use crate::memory::{MemoryValue};

pub struct ScopeContext {
    scopes: VecDeque<Scope>
}

impl ScopeContext {
    pub fn enter(&mut self) {
        self.scopes.push_back(Scope::new());
    }

    pub fn leave(&mut self) {
        self.scopes.pop_back();
    }

    pub fn leave_last_n(&mut self, n: usize) {
        let mut i = n;
        while i > 0 {
            self.scopes.pop_back();
            i -= 1;
        }
    }

    pub fn last_n_is_valid(&self, scope: usize) -> bool {
        let len = self.scopes.len();
        if len == 0 {
            return false;
        }
        if self.scopes.len() - 1 < scope {
            false
        } else {
            true
        }
    }
    
    pub fn current_mut_unchecked(&mut self) -> &mut Scope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unchecked(&self) -> &Scope {
        self.scopes.back().expect("should not happend")
    }

    pub fn last_one_unchecked(&self) -> &Scope {
        /*
         * 获取前一个作用域
         * */
        self.last_n_unchecked(1)
    }

    pub fn last_one_mut_unchecked(&mut self) -> &mut Scope {
        self.last_n_mut_unchecked(1)
    }

    pub fn last_n_unchecked(&self, n: usize) -> &Scope {
        // println!("len: {}, n: {}", self.scopes.len(), n);
        let index = self.scopes.len() - 1 - n;
        self.scopes.get(index).expect(&format!("len: {}, index: {}", self.scopes.len(), index))
    }

    pub fn last_n_mut_unchecked(&mut self, n: usize) -> &mut Scope {
        let len = self.scopes.len();
        let index = len - 1 - n;
        self.scopes.get_mut(index).expect(&format!("len: {}, index: {}", len, index))
    }

    fn get_addr_ref_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr, memory: &ThreadMemory
        , index: usize, scope: usize)
        -> RefPtr {
        // println!("scope: {}, addr_typ: {:?}", scope, addr.typ_ref());
        match addr.typ_ref() {
            AddressType::AddrRef => {
                // self.current_unchecked().print_ref_param_addr_mapping();
                // self.last_n_unchecked(1).print_ref_param_addr_mapping();
                let ref_addr = self.last_n_unchecked(scope).get_ref_param_addr_unchecked(
                    addr.addr_ref());
                /*
                println!("{:?}", ref_addr);
                self.current_unchecked().print_addr_mapping();
                self.last_n_unchecked(1).print_addr_mapping();
                */
                self.get_addr_ref_data_unchecked(ref_addr
                    , link_static, memory
                    , index
                    // , index+ref_addr.addr_ref().index_clone() as usize
                    , scope+ref_addr.addr_ref().scope_clone())
            },
            _ => {
                // self.last_n_unchecked(1).print_ref_param_addr_mapping();
                let mut a = addr.clone();
                *a.addr_mut().index_mut() += index as u64;
                self.last_n_unchecked(scope).get_data_unchecked(
                    &a, link_static, memory)
            }
        }
    }

    pub fn get_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr, memory: &ThreadMemory)
        -> RefPtr {
        self.get_addr_ref_data_unchecked(
            addr, link_static, memory, addr.addr_ref().index_clone() as usize
            , addr.addr_ref().scope_clone())
    }

    pub fn get_addr_ref_data_addr_unchecked(&self, addr: &AddressValue
        , scope: usize) -> (usize, &MemoryValue) {
        match addr.typ_ref() {
            AddressType::AddrRef => {
                let ref_addr = self.last_n_unchecked(scope).get_ref_param_addr_unchecked(
                    addr.addr_ref());
                self.get_addr_ref_data_addr_unchecked(ref_addr
                    , scope+ref_addr.addr_ref().scope_clone())
            },
            _ => {
                (scope, self.last_n_unchecked(scope).get_data_addr_unchecked(addr.addr_ref()))
            }
        }
    }

    pub fn get_data_addr_unchecked(&self, addr: &AddressValue) -> &MemoryValue {
        self.get_addr_ref_data_addr_unchecked(addr, addr.addr_ref().scope_clone()).1
    }

    pub fn get_data_scope_addr_unchecked(&self, addr: &AddressValue) -> (usize, &MemoryValue) {
        self.get_addr_ref_data_addr_unchecked(addr, addr.addr_ref().scope_clone())
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}

