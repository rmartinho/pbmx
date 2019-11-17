use libc::c_void;
use std::{marker::PhantomData, ops::Try, option::NoneError, ptr};

#[repr(transparent)]
pub struct Opaque<T>(*mut c_void, PhantomData<*mut T>);

impl<T> Opaque<T> {
    pub unsafe fn wrap(r: T) -> Self {
        Self(Box::into_raw(box r) as _, PhantomData)
    }

    pub unsafe fn delete(self) {
        if !self.0.is_null() {
            Box::from_raw(self.0 as *mut T);
        }
    }

    pub unsafe fn boxed(self) -> Option<Box<T>> {
        if !self.0.is_null() {
            Some(Box::from_raw(self.0 as _))
        } else {
            None
        }
    }

    pub unsafe fn as_ref(&self) -> Option<&T> {
        (self.0 as *const T).as_ref()
    }

    pub unsafe fn as_mut(&mut self) -> Option<&mut T> {
        (self.0 as *mut T).as_mut()
    }
}

impl<T> Try for Opaque<T> {
    type Error = NoneError;
    type Ok = *mut T;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        if self.0.is_null() {
            Err(NoneError)
        } else {
            Ok(self.0 as _)
        }
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self(v as _, PhantomData)
    }

    fn from_error(_: Self::Error) -> Self {
        Self(ptr::null_mut(), PhantomData)
    }
}
