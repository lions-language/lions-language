use proc_macro;

use proc_macro::TokenStream;
use quote::{quote, format_ident};
use syn::{DeriveInput, Ident, Type};

type CB = fn(struct_ident: &Ident, field_ident: &Ident, typ: &Type) -> TokenStream;

fn iter(input: TokenStream, f: CB) -> TokenStream {
    let derive: DeriveInput = syn::parse(input).unwrap();
    let ident = &derive.ident;
    let s = match derive.data {
        syn::Data::Struct(s) => {
            s
        },
        _ => {
            unimplemented!("not struct");
        }
    };  
    let n = match s.fields {
        syn::Fields::Named(n) => {
            n
        },
        _ => {
            unimplemented!("not named struct");
        }
    };
    let fields = n.named;
    let mut ts = TokenStream::new();
    for field in fields.iter() {
        let typ = &field.ty;
        let field_ident = match &field.ident {
            Some(id) => id,
            None => {
                /*
                 * tuple struct
                 * */
                unimplemented!("tuple struct");
            }
        };
        let t = f(&ident, &field_ident, &typ);
        ts.extend::<TokenStream>(t);
    }
    ts
}

/*
 * 为结构中的每一个成员提供获取接口
 * */
fn ref_move_cb(struct_ident: &Ident, field_ident: &Ident, typ: &Type) -> TokenStream {
    let ref_id = format_ident!("{}_ref", &field_ident);
    let expanded = quote! {
        impl #struct_ident {
            pub fn #ref_id(&self) -> &#typ {
                &self.#field_ident
            }

            pub fn #field_ident(self) -> #typ {
                self.#field_ident
            }
        }
    };
    expanded.into()
}

pub fn ref_move(input: TokenStream) -> TokenStream {
    iter(input, ref_move_cb)
}

fn clone_cb(struct_ident: &Ident, field_ident: &Ident, typ: &Type) -> TokenStream {
    let clone_id = format_ident!("{}_clone", &field_ident);
    let expanded = quote! {
        impl #struct_ident {
            pub fn #clone_id(&self) -> #typ {
                self.#field_ident.clone()
            }
        }
    };
    expanded.into()
}

pub fn clone(input: TokenStream) -> TokenStream {
    iter(input, clone_cb)
}

