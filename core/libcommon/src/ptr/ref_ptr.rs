use super::{RefPtr};

impl RefPtr {
    pub fn from_ref<T>(item: &T) -> Self {
        RefPtr::from_ref_typ::<T>(item, 0)
    }

    pub fn from_ref_typ<T>(item: &T, typ: u8) -> Self {
        Self {
            ptr: item as *const T as usize,
            typ: typ
        }
    }

    pub fn typ_ref(&self) -> &u8 {
        &self.typ
    }

    pub fn typ_clone(&self) -> u8 {
        self.typ.clone()
    }

    pub fn new_null() -> Self {
        Self{
            ptr: 0,
            typ: 0
        }
    }

    pub fn is_null(&self) -> bool {
        self.ptr == 0
    }

    pub fn as_ref<T>(&self) -> &T {
        unsafe {
            (self.ptr as *const T).as_ref().expect("should not happend")
        }
    }

    pub fn as_mut<T>(&mut self) -> &mut T {
        unsafe {
            (self.ptr as *mut T).as_mut().expect("should not happend")
        }
    }
}

impl Default for RefPtr {
    fn default() -> Self {
        RefPtr::new_null()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashMap;

    #[test]
    #[ignore]
    fn ref_ptr_test() {
    }
}

