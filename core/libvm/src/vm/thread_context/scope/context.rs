use libtype::{
    AddressKey
    , AddressValue, AddressType};
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
        self.last_n_unchecked(0)
    }

    pub fn last_one_mut_unchecked(&mut self) -> &mut Scope {
        self.last_n_mut_unchecked(0)
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

    pub fn last_one(&self) -> Option<&Scope> {
        self.last_n(0)
    }

    pub fn last_n(&self, n: usize) -> Option<&Scope> {
        let len = self.scopes.len();
        if len == 0 || len - 1 < n {
            return None;
        }
        if len - 1 == 0 {
            return self.scopes.back();
        }
        let index = len - 1 - n;
        self.scopes.get(index)
    }

    pub fn last_one_mut(&mut self) -> Option<&mut Scope> {
        self.last_n_mut(0)
    }

    pub fn last_n_mut(&mut self, n: usize) -> Option<&mut Scope> {
        let len = self.scopes.len();
        if len == 0 || len - 1 < n {
            return None;
        }
        if len -1 == 0 {
            return self.scopes.back_mut();
        }
        let index = len - 1 - n;
        self.scopes.get_mut(index)
    }

    fn get_addr_ref_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr, memory: &ThreadMemory
        , offset: usize, scope: usize
        , top_addr: AddressKey)
        -> RefPtr {
        // println!("scope: {}, addr_typ: {:?}", scope, addr.typ_ref());
        // match addr.root_typ_ref() {
        match addr.typ_ref() {
            AddressType::AddrRef => {
                // self.current_unchecked().print_ref_param_addr_mapping();
                // self.last_n_unchecked(1).print_ref_param_addr_mapping();
                /*
                let mut ak = addr.addr_clone();
                let of = ak.offset_clone();
                if of > 0 {
                    *ak.index_mut() -= of as u64;
                }
                /*
                println!("offset: {}, index: {}", of, addr.addr_ref().index_clone());
                */
                println!("*** {:?}, {}, {} ***", ak, of, offset);
                let ref_addr = self.last_n_unchecked(scope).get_ref_param_addr_unchecked(
                    &ak);
                */
                let ref_addr = self.last_n_unchecked(scope).get_ref_param_addr_unchecked(
                    addr.addr_ref()).clone();
                // *ref_addr.typ_mut() = addr.typ_clone();
                // println!("{:?}", ref_addr);
                /*
                println!("{:?}", ref_addr);
                self.current_unchecked().print_addr_mapping();
                self.last_n_unchecked(1).print_addr_mapping();
                */
                self.get_addr_ref_data_unchecked(&ref_addr
                    , link_static, memory
                    , offset + ref_addr.addr_ref().offset_clone()
                    // , index+ref_addr.addr_ref().index_clone() as usize
                    , scope + ref_addr.addr_ref().scope_clone()
                    , top_addr)
            },
            _ => {
                // self.last_n_unchecked(1).print_ref_param_addr_mapping();
                /*
                let a = if offset > 0 {
                    AddressValue::new(addr.typ_clone()
                        , top_addr)
                } else {
                    let mut a = addr.clone();
                    println!("{:?}, {}", a, offset);
                    *a.addr_mut().index_mut() += offset as u64;
                    a
                };
                */
                /*
                let mut a = addr.clone();
                *a.addr_mut().index_mut() += offset as u64;
                match a.typ_ref() {
                    AddressType::AddrRef => {
                        *a.root_typ_mut() = a.typ_clone();
                        self.get_addr_ref_data_unchecked(&a
                            , link_static, memory
                            , offset
                            , scope
                            , top_addr)
                    },
                    _ => {
                        self.last_n_unchecked(scope).get_data_unchecked(
                            &a, link_static, memory)
                    }
                }
                */
                self.last_n_unchecked(scope).get_data_unchecked(
                    addr, link_static, memory)
            }
        }
    }

    pub fn get_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr, memory: &ThreadMemory)
        -> RefPtr {
        self.get_addr_ref_data_unchecked(
            addr, link_static, memory
            , addr.addr_ref().offset_clone()
            , addr.addr_ref().scope_clone()
            , addr.addr_clone())
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
        let mut scopes = VecDeque::new();
        // scopes.push_back(Scope::new());
        Self {
            scopes: scopes
        }
    }
}

