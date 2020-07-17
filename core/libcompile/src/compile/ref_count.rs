use std::collections::HashMap;

pub struct Counter {
    count: u64
}

impl Counter {
    pub fn alloc(&mut self) {
        self.count += 1;
    }

    pub fn free(&mut self) {
        self.count -= 1;
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }

    pub fn is_zero(&self) -> bool {
        if self.count == 0 {
            true
        } else {
            false
        }
    }

    pub fn new() -> Self {
        Self {
            count: 0
        }
    }
}

/*
 * 引用计数 (存储的都是当前作用域中拥有所有权的变量)
 * */
pub struct RefCounter {
    refs: HashMap<u64, Counter>
}

impl RefCounter {
    pub fn find(&self, r: &u64) -> Option<&Counter> {
        self.refs.get(r)
    }

    pub fn find_mut(&mut self, r: &u64) -> Option<&mut Counter> {
        self.refs.get_mut(r)
    }

    pub fn count_alloc_panic(&mut self, r: &u64) {
        match self.find_mut(r) {
            Some(v) => {
                v.alloc();
            },
            None => {
                panic!("should not happend");
            }
        }
    }

    pub fn count_clear_panic(&mut self, r: &u64) {
        match self.find_mut(r) {
            Some(v) => {
                v.clear();
            },
            None => {
                panic!("should not happend");
            }
        }
    }

    pub fn create(&mut self, r: u64) {
        self.refs.insert(r, Counter::new());
    }

    pub fn remove(&mut self, r: &u64) {
        self.refs.remove(r);
    }

    pub fn iter_zero<F>(&mut self, mut f: F)
        where F: FnMut(u64) {
        let mut rms = Vec::new();
        for (k, v) in self.refs.iter() {
            if v.is_zero() {
                (f)(*k);
                rms.push(*k);
            }
        }
        for item in rms.iter() {
            self.refs.remove(item);
        }
    }

    pub fn new() -> Self {
        Self {
            refs: HashMap::new()
        }
    }
}

/*
impl<'a> Iterator for &'a RefCounter {
    type Item = &'a Counter;
    fn next(&mut self) -> Option<Self::Item> {
        self.refs.
        None
    }
}
*/

