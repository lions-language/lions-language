use libtype::{AddressValue, AddressType
    , AddressKey, Data};
use libcommon::ptr::RefPtr;
use liblink::statics::LinkStatic;
use crate::memory::stack::rand::RandStack;
use crate::vm::addr_mapping::{AddressMapping};
use crate::vm::thread_context::{ThreadMemory};
use crate::memory::{Rand, MemoryValue};

pub struct Scope {
    addr_mapping: AddressMapping
}

impl Scope {
    pub fn get_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr, memory: &ThreadMemory)
        -> RefPtr {
        /*
         * 根据编译期的地址获取数据
         * */
        match addr.typ_ref() {
            AddressType::Static => {
                /*
                 * 数据存储在静态区域中
                 *  1. 获取绑定的实际地址
                 *  2. 根据实际地址, 在静态区查找数据
                 * */
                let static_addr = self.addr_mapping.get_unwrap(addr.addr_ref());
                let data = link_static.as_ref::<LinkStatic>().read_uncheck(
                    static_addr.get_ref());
                RefPtr::from_ref::<Data>(data)
            },
            AddressType::Stack => {
                /*
                 * 数据存储在栈区中
                 *  1. 获取绑定的实际地址
                 *  2. 根据实际地址, 在栈区中查找数据
                 * */
                let stack_addr = self.addr_mapping.get_unwrap(addr.addr_ref());
                let data = memory.stack_data_ref().get_unwrap(stack_addr);
                RefPtr::from_ref::<Data>(data)
            },
            _ => {
                unimplemented!("{:?}", addr.typ_ref());
            }
        }
    }

    pub fn take_data_unchecked(&mut self, addr: &AddressValue
        , link_static: &RefPtr, memory: &mut ThreadMemory)
        -> Data {
        match addr.typ_ref() {
            AddressType::Static => {
                panic!("static should not be taked");
            },
            AddressType::Stack => {
                let stack_addr = self.addr_mapping.get_unwrap(addr.addr_ref());
                let data = memory.stack_data_mut().take_unwrap(stack_addr);
                self.addr_mapping.remove(addr.addr_clone());
                data
            },
            _ => {
                unimplemented!("{:?}", addr.typ_ref());
            }
        }
    }

    pub fn get_data_addr_unchecked(&self, addr: &AddressValue) -> &MemoryValue {
        self.addr_mapping.get_unwrap(addr.addr_ref())
    }

    pub fn alloc_and_write_data(&mut self, addr: &AddressValue
        , data: Data, mut memory: RefPtr) {
        // println!("write: {:?} => {:?}", addr, &data);
        let memory = memory.as_mut::<ThreadMemory>();
        match addr.typ_ref() {
            AddressType::Stack => {
                /*
                 * 1. 在栈区分配一个空间, 并将数据存入
                 * 2. 将编译期的地址和实际的地址进行绑定
                 * */
                let stack_addr = memory.stack_data.alloc(data);
                self.addr_mapping.bind(addr.addr_clone()
                    , stack_addr);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    pub fn alloc_and_write_static(&mut self, addr: &AddressValue
        , static_addr: AddressKey) {
        /*
         * 将给定的编译期地址与静态区的地址进行绑定
         * */
        self.addr_mapping.bind(addr.addr_clone()
            , MemoryValue::new(static_addr));
    }

    pub fn add_bind(&mut self, addr: AddressKey
        , src_addr: AddressKey) {
        self.addr_mapping.bind(addr
            , MemoryValue::new(src_addr));
    }

    pub fn remove_bind(&mut self, addr: AddressKey) {
        self.addr_mapping.remove(addr);
    }

    pub fn print_addr_mapping(&self) {
        self.addr_mapping.print();
    }

    pub fn new() -> Self {
        Self {
            addr_mapping: AddressMapping::new()
        }
    }
}

pub mod context;
