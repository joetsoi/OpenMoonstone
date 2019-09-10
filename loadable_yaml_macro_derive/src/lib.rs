#![recursion_limit = "128"]
extern crate proc_macro;

use crate::proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(LoadableYaml)]
pub fn loadable_yaml_macro_derive(input: TokenStream) -> TokenStream {
    // Construct a representation of Rust code as a syntax tree
    // that we can manipulate
    let ast = syn::parse(input).unwrap();

    // Build the trait implementation
    impl_loadable_yaml_macro(&ast)
}

fn impl_loadable_yaml_macro(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl warmy::Load<Context, warmy::SimpleKey> for #name {
            type Error = crate::error::LoadError<crate::manager::GameYaml>;
            fn load(
                key: warmy::SimpleKey,
                _store: &mut warmy::Storage<Context, warmy::SimpleKey>,
                ctx: &mut ggez::Context,
            ) -> Result<warmy::Loaded<Self, warmy::SimpleKey>, Self::Error> {
                match key {
                    warmy::SimpleKey::Logical(key) => {
                        let file = ggez::filesystem::open(ctx, key.as_str())?;
                        let yaml: serde_yaml::Value = serde_yaml::from_reader(file)?;
                        let name: #name = serde_yaml::from_value(yaml)?;
                        // let file = ggez::filesystem::open(ctx, key.as_str()).map_err(compat_error::err_from)?;
                        // let yaml: serde_yaml::Value = serde_yaml::from_reader(file).map_err(compat_error::err_from)?;
                        // let name: #name = serde_yaml::from_value(yaml).map_err(compat_error::err_from)?;
                        Ok(warmy::Loaded::from(name))
                    }
                    // warmy::SimpleKey::Path(_) => Err(err_msg("error").compat())
                    warmy::SimpleKey::Path(_) => Err(crate::error::LoadError::PathLoadNotImplemented)
                }
            }
        }
    };
    gen.into()
}
