pub mod authz;
pub mod console;
pub mod deploy;
pub mod dns;
pub mod endpoints;
// pub mod firewall;
pub mod init;
pub mod providers;
pub mod proxy;
pub mod registry;
pub mod node;
pub mod refresh;
pub mod relayer;
pub mod sdl;
pub mod sites;
pub mod test;
pub mod testnet;
pub mod vpn;

/// Attach compile-time `--examples` documentation to a clap Args struct.
///
/// Takes a struct definition and a path literal (relative to the **call site** file),
/// appends an `examples: bool` field, and generates a `print_examples_if_requested`
/// method that prints the embedded markdown and returns `true` when `--examples` is passed.
///
/// # Usage
/// ```rust,ignore
/// with_examples! {
///     #[derive(clap::Args, Debug)]
///     pub struct FooArgs {
///         #[arg(long)]
///         pub bar: bool,
///     }
///     => "../docs/foo.md"
/// }
/// ```
#[macro_export]
macro_rules! with_examples {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$fa:meta])* $fv:vis $field:ident : $ty:ty ),*
            $(,)?
        }
        => $doc_path:literal
    ) => {
        $(#[$attr])*
        $vis struct $name {
            $( $(#[$fa])* $fv $field : $ty, )*
            /// Print usage examples and exit.
            #[arg(long, help = "Print usage examples and exit")]
            pub examples: bool,
        }

        impl $name {
            /// If `--examples` was passed, print the embedded markdown and return `true`.
            /// Callers should return early when this returns `true`.
            pub fn print_examples_if_requested(&self) -> bool {
                if self.examples {
                    let doc = include_str!($doc_path);
                    // Strip YAML frontmatter (--- delimited) if present
                    let content = if doc.starts_with("---") {
                        doc.splitn(3, "---").nth(2).unwrap_or(doc).trim_start()
                    } else {
                        doc
                    };
                    println!("{}", content);
                    true
                } else {
                    false
                }
            }
        }
    };
}
