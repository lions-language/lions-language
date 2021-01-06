use libtype::{AddressValue, AddressType
    , AddressKey, Data};
use libcommon::ptr::RefPtr;
use libcommon::address::{FunctionAddrValue};
use liblink::statics::LinkStatic;
use crate::memory::stack::rand::RandStack;
use crate::vm::addr_mapping::{AddressMapping};
use crate::vm::thread_context::{ThreadMemory};
use crate::memory::{Rand, MemoryValue};

struct ParamRef {
    data_addr: MemoryValue
}

pub struct Scope {
    addr_mapping: AddressMapping,
    ref_param_addr_mapping: AddressMapping,
    /*
     * 记录当前作用域的结果 数据地址
     * */
    result_data_addr: AddressValue,
    /*
     * 记录函数调用前的位置
     * */
    after_func_call_addr: Option<FunctionAddrValue>,
    block_addr: Option<FunctionAddrValue>
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
                    static_addr.addr_value_ref().addr_ref());
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

    pub fn get_data_by_data_addr_unchecked(&self, data_addr: &MemoryValue
        , link_static: &RefPtr, memory: &ThreadMemory)
        -> RefPtr {
        match data_addr.addr_value_ref().typ_ref() {
            AddressType::Static => {
                /*
                 *  根据实际地址, 在静态区查找数据
                 * */
                let data = link_static.as_ref::<LinkStatic>().read_uncheck(
                    data_addr.addr_value_ref().addr_ref());
                RefPtr::from_ref::<Data>(data)
            },
            AddressType::Stack => {
                /*
                 * 数据存储在栈区中
                 *  1. 获取绑定的实际地址
                 *  2. 根据实际地址, 在栈区中查找数据
                 * */
                let data = memory.stack_data_ref().get_unwrap(data_addr);
                RefPtr::from_ref::<Data>(data)
            },
            _ => {
                unimplemented!("{:?}", data_addr.addr_value_ref().typ_ref());
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

    pub fn get_data_addr_unchecked(&self, addr: &AddressKey) -> &MemoryValue {
        self.addr_mapping.get_unwrap(addr)
    }

    pub fn get_ref_param_addr_unchecked(&self, addr: &AddressKey) -> &AddressValue {
        self.ref_param_addr_mapping.get_unwrap(addr).addr_value_ref()
    }

    pub fn alloc_or_update_data(&mut self, addr: &AddressValue
        , data: Data, mut memory: RefPtr) {
        // println!("write: {:?} => {:?}", addr, &data);
        let memory = memory.as_mut::<ThreadMemory>();
        match addr.typ_ref() {
            AddressType::Stack => {
                /*
                 * 1. 在栈区分配一个空间, 并将数据存入
                 * 2. 将编译期的地址和实际的地址进行绑定
                 * */
                match memory.stack_data.get_mut(&MemoryValue::new(addr.clone())) {
                    Some(v) => {
                        *v = data;
                    },
                    None => {
                        let stack_addr = memory.stack_data.alloc(addr.typ_clone(), data);
                        self.addr_mapping.bind(addr.addr_clone()
                            , stack_addr);
                    }
                }
            },
            _ => {
                unimplemented!();
            }
        }
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
                if memory.stack_data.exists(&MemoryValue::new(addr.clone())) {
                    return;
                }
                let stack_addr = memory.stack_data.alloc(addr.typ_clone(), data);
                self.addr_mapping.bind(addr.addr_clone()
                    , stack_addr);
            },
            _ => {
                unimplemented!();
            }
        }
    }

    pub fn free_data(&mut self, addr: MemoryValue
        , mut memory: RefPtr) {
        let memory = memory.as_mut::<ThreadMemory>();
        match addr.addr_value_ref().typ_ref() {
            AddressType::Stack => {
                self.addr_mapping.remove(addr.addr_value_ref().addr_clone());
                memory.stack_data.free(addr);
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
            , MemoryValue::new(AddressValue::new(AddressType::Static, static_addr)));
    }

    pub fn add_bind(&mut self, addr: AddressKey
        , src_addr_value: AddressValue) {
        self.addr_mapping.bind(addr
            , MemoryValue::new(src_addr_value));
    }

    pub fn add_ref_param_addr_bind(&mut self, addr: AddressKey
        , src_addr: AddressValue) {
        // println!("{:?} {:?}", addr, src_addr);
        self.ref_param_addr_mapping.bind(addr
            , MemoryValue::new(src_addr));
    }

    pub fn remove_bind(&mut self, addr: AddressKey) {
        self.addr_mapping.remove(addr);
    }

    pub fn set_result_data_addr(&mut self, addr_value: AddressValue) {
        *&mut self.result_data_addr = addr_value;
    }

    pub fn get_result_data_addr(&self) -> &AddressValue {
        &self.result_data_addr
    }

    pub fn set_after_func_call_addr(&mut self, addr: FunctionAddrValue) {
        *&mut self.after_func_call_addr = Some(addr);
    }

    pub fn get_after_func_call_addr(&self) -> &Option<FunctionAddrValue> {
        &&self.after_func_call_addr
    }

    pub fn set_block_addr(&mut self, addr: FunctionAddrValue) {
        *&mut self.block_addr = Some(addr);
    }

    pub fn get_block_addr(&self) -> &Option<FunctionAddrValue> {
        &self.block_addr
    }

    pub fn get_block_addr_unchecked(&self) -> FunctionAddrValue {
        self.block_addr.as_ref().expect("should not happend").clone()
    }

    pub fn print_ref_param_addr_mapping(&self) {
        self.ref_param_addr_mapping.print();
    }

    pub fn print_addr_mapping(&self) {
        self.addr_mapping.print();
    }

    pub fn new() -> Self {
        Self {
            addr_mapping: AddressMapping::new(),
            ref_param_addr_mapping: AddressMapping::new(),
            result_data_addr: AddressValue::new_invalid(),
            after_func_call_addr: None,
            block_addr: None
        }
    }
}

pub mod context;
