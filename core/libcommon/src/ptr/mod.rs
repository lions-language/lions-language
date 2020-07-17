#[derive(Debug, Clone)]
pub struct RefPtr(usize);

impl RefPtr {
    pub fn from_ref<T>(item: &T) -> Self {
        Self(item as *const T as usize)
    }

    pub fn new_null() -> Self {
        Self(0)
    }

    pub fn is_null(&self) -> bool {
        self.0 == 0
    }

    pub fn as_ref<T>(&self) -> &T {
        unsafe {
            (self.0 as *const T).as_ref().expect("should not happend")
        }
    }

    pub fn clone(&self) -> Self {
        Self(self.0)
    }
}
