macro_rules! create_hash {
    ( $(#[ $attr:meta ])* pub struct $id:ident (Hash< $n:ty >) = $custom:expr ; ) => {
        $(#[ $attr ])*
        #[derive(Clone)]
        pub struct $id($crate::crypto::Hash<$n>);

        impl ::std::default::Default for $id {
            fn default() -> Self {
                Self($crate::crypto::Hash::new($custom))
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
}

macro_rules! create_xof {
    ( $(#[ $attr:meta ])* pub struct $id:ident = $custom:expr ; ) => {
        $(#[ $attr ])*
        #[derive(Clone)]
        pub struct $id($crate::crypto::Xof);

        impl ::std::default::Default for $id {
            fn default() -> Self {
                Self($crate::crypto::Xof::new($custom))
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
