/*
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::DeriveInput;

#[proc_macro_derive(ToStd)]
pub fn to_std_macro(input: TokenStream) -> TokenStream {
    let derive: DeriveInput = syn::parse(input).unwrap();

    let ident = &derive.ident;
    let s = match derive.data {
        syn::Data::Struct(s) => {
            s
        },
        _ => {
            panic!("must be struct");
        }
    };  
    let n = match s.fields {
        syn::Fields::Named(n) => {
            n
        },
        _ => {
            panic!("not named");
        }
    };  
    let named = n.named;
    if named.is_empty() {
        panic!("field must len more than 1");
    }   
    let field = named.first().expect("should not happend");

    let expanded = quote! {
        impl #ident {
            pub fn to_primeval(self) -> #field {
                self.value
            }
        }
    };  

    expanded.into()
}
*/

pub mod int8;
pub mod int16;
pub mod int32;
pub mod int64;
pub mod uint8;
pub mod uint16;
pub mod uint32;
pub mod uint64;
pub mod float32;
pub mod float64;
