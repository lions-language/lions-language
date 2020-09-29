use super::{HeapPtr, Heap};

/*
pub struct HeapGet<T> {
    value: Heap<T>
}
*/

impl HeapPtr {
    pub fn alloc<T>(value: T) -> Self {
        HeapPtr::alloc_with_typ(value, 0)
    }

    pub fn alloc_with_typ<T>(value: T, typ: u8) -> Self {
        let b = Heap::new(value);
        let bp = Heap::into_raw(b);
        let bpval = bp as usize;
        let o = Self {
            ptr: bpval,
            typ: typ
        };
        std::mem::forget(unsafe{Heap::from_raw(bp)});
        o
    }

    /*
     * 获取并在作用域结束的时候释放
     * */
    pub fn take<T>(self) -> Heap<T> {
        unsafe{Heap::from_raw(self.ptr as *mut T)}
    }

    /*
    pub fn get<T>(&self) -> HeapGet<T> {
        let b = unsafe{Heap::from_raw(self.ptr as *mut T)};
        HeapGet::<T>{
            value: b
        }
    }
    */

    pub fn pop<T>(&self) -> Heap<T> {
        unsafe{Heap::from_raw(self.ptr as *mut T)}
    }

    pub fn push<T>(&self, b: Heap<T>) {
        std::mem::forget(b);
    }

    pub fn get_fn<T, F: FnMut(Heap<T>) -> Heap<T>>(&self, mut f: F) {
        let b = unsafe{Heap::from_raw(self.ptr as *mut T)};
        let b = f(b);
        std::mem::forget(b);
    }

    pub fn free<T>(&self) {
        let b = unsafe{Heap::from_raw(self.ptr as *mut T)};
        std::mem::drop(b);
    }
    
    pub fn typ_ref(&self) -> &u8 {
        &self.typ
    }

    pub fn new_null() -> Self {
        Self {
            ptr: 0,
            typ: 0
        }
    }
}

impl Default for HeapPtr {
    fn default() -> Self {
        Self::default()
    }
}

/*
impl<T> Drop for HeapGet<T> {
    fn drop(&mut self) {
        let bp = Heap::into_raw(self.value);
        std::mem::forget(self.value);
    }
}
*/

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore]
    fn heap_ptr_test() {
        let p = HeapPtr::alloc(String::from("hello"));
        let value = p.pop::<String>();
        println!("{}", value);
        p.push(value);
        println!("{}", p.pop::<String>());
    }

    struct Test {
    }

    impl Test {
        fn print(&self) {
        }
    }

    impl Drop for Test {
        fn drop(&mut self) {
            println!("drop");
        }
    }

    #[test]
    fn heap_ptr_ownership_test() {
        let p = HeapPtr::alloc(Test{});
        {
            /*
             * 即使不赋值给变量, pop 之后的作用域也会被转移, 作用域结束后, 同样会被销毁
             * */
            p.pop::<Test>().print();
        }
    }
}

