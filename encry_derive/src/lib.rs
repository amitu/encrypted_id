extern crate proc_macro;
extern crate proc_macro2;
#[macro_use]
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use syn::{
    DeriveInput, ItemStruct,
    parse::{Parse, ParseStream, Result}, LitStr, Token,
};


struct PathArgs {
    table_name: String,
}

mod keyword {
    syn::custom_keyword!(table_name);
}

impl Parse for PathArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        input.parse::<keyword::table_name>()?;
        input.parse::<Token![=]>()?;
        let path: LitStr = input.parse()?;
        Ok(PathArgs{table_name: path.value()})
    }
}


#[proc_macro_attribute]
pub fn endecrypt(meta: TokenStream, input: TokenStream) -> TokenStream {
    let input_clone = input.clone();
    let table_name = parse_macro_input!(meta as PathArgs).table_name;
    let struct_item: ItemStruct = parse_macro_input!(input as ItemStruct);
    let derive_input = parse_macro_input!(input_clone as DeriveInput);
    let ident = struct_item.ident;
    quote!(

        #derive_input

        impl Encrypt for #ident {
            fn ekey(id: u64) -> EncryptResult<String> {
                encode_ekey_util(id, #table_name)
            }
        }

        impl Decrypt for #ident {
            fn dkey(ekey: &str) -> EncryptResult<u64> {
                decode_ekey_util(ekey, #table_name)
            }
        }

    )
    .into()
}