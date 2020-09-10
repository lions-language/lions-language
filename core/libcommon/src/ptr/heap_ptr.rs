use super::{HeapPtr, Heap};

impl HeapPtr {
    pub fn alloc<T>(value: T) -> Self {
        let b = Heap::new(value);
        let bp = Heap::into_raw(b);
        let bpval = bp as usize;
        let o = Self {
            ptr: bpval
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn heap_ptr_test() {
        let p = HeapPtr::alloc(String::from("hello"));
        let value = p.pop::<String>();
        println!("{}", value);
        p.push(value);
        println!("{}", p.pop::<String>());
    }
}

