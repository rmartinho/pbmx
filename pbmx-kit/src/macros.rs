macro_rules! create_hash {
    ( $(#[ $attr:meta ])* pub struct $id:ident (Hash< $n:ty >) = $domain:expr ; ) => {
        $(#[ $attr ])*
        #[derive(Clone)]
        pub struct $id($crate::crypto::Hash<$n>);
        create_hash!(__hash $id($n) = $domain);
    };
    ( $(#[ $attr:meta ])* struct $id:ident (Hash< $n:ty >) = $domain:expr ; ) => {
        $(#[ $attr ])*
        #[derive(Clone)]
        pub(crate) struct $id($crate::crypto::Hash<$n>);
        create_hash!(__hash $id($n) = $domain);
    };
    ( $(#[ $attr:meta ])* pub struct $id:ident ( Xof ) = $domain:expr ; ) => {
        $(#[ $attr ])*
        #[derive(Clone)]
        pub struct $id($crate::crypto::Xof);
        create_hash!(__xof $id = $domain );
    };
    ( $(#[ $attr:meta ])* struct $id:ident ( Xof ) = $domain:expr ; ) => {
        $(#[ $attr ])*
        #[derive(Clone)]
        pub(crate) struct $id($crate::crypto::Xof);
        create_hash!(__xof $id = $domain);
    };
    ( __hash $id:ident ( $n:ty ) = $domain:expr ) => {
        impl ::std::default::Default for $id {
            fn default() -> Self {
                Self($crate::crypto::Hash::new($domain))
            }
        }

        impl ::digest::FixedOutput for $id {
            type OutputSize = $n;

            fn fixed_result(self) -> ::digest::generic_array::GenericArray<u8, Self::OutputSize> {
                self.0.fixed_result()
            }
        }

        impl ::digest::BlockInput for $id {
            type BlockSize = ::digest::generic_array::typenum::U168;
        }

        impl ::digest::Input for $id {
            fn input<B: ::std::convert::AsRef<[u8]>>(&mut self, data: B) {
                self.0.input(data)
            }
        }

        impl ::digest::Reset for $id {
            fn reset(&mut self) {
                self.0.reset()
            }
        }

        impl ::std::io::Write for $id {
            fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
                self.0.write(buf)
            }

            fn flush(&mut self) -> ::std::io::Result<()> {
                self.0.flush()
            }
        }
    };
    ( __xof $id:ident = $domain:expr ) => {
        impl ::std::default::Default for $id {
            fn default() -> Self {
                Self($crate::crypto::Xof::new($domain))
            }
        }

        impl ::digest::ExtendableOutput for $id {
            type Reader = <$crate::crypto::Xof as ::digest::ExtendableOutput>::Reader;

            fn xof_result(self) -> Self::Reader {
                self.0.xof_result()
            }
        }

        impl ::digest::Input for $id {
            fn input<B: ::std::convert::AsRef<[u8]>>(&mut self, data: B) {
                self.0.input(data)
            }
        }

        impl ::digest::Reset for $id {
            fn reset(&mut self) {
                self.0.reset()
            }
        }

        impl ::std::io::Write for $id {
            fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
                self.0.write(buf)
            }

            fn flush(&mut self) -> ::std::io::Result<()> {
                self.0.flush()
            }
        }
    };
}

// Copy&pasted from nom's source to avoid deprecation warnings
macro_rules! ws {
    ($i:expr, $($args:tt)*) => {
        {
            use ::nom::Err;
            use ::nom::lib::std::result::Result::*;
            use ::nom::character::complete::multispace0;

            match sep!($i, multispace0, $($args)*) {
                Err(e) => Err(e),
                Ok((i1,o))    => {
                    match (multispace0)(i1) {
                        Err(e) => Err(Err::convert(e)),
                        Ok((i2,_))    => Ok((i2, o))
                    }
                }
            }
        }
    }
}
