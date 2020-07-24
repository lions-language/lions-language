use libtype::function::Function;
use phf::phf_map;

lazy_static!{
    static ref FUNCTIONS: phf::Map<&'static str, u32> = { 
        phf_map! {
            "println" => 0,
        }
    };

    static ref FUNCTION_VEC: Vec<&'static Function> = { 
        let mut v = Vec::new();
        v.push(&*print::PRINTLN);
        v
    };
}

pub fn get_method(func_str: &str) -> Option<&'static Function> {
    let index = match FUNCTIONS.get(func_str) {
        Some(index) => {
            index
        },
        None => {
            return None;
        }
    };  
    if *index > FUNCTION_VEC.len() as u32 {
        return None;
    }   
    match FUNCTION_VEC.get(*index as usize) {
        Some(v) => {
            Some(v)
        },
        None => {
            None
        }
    }   
}

pub mod print;
