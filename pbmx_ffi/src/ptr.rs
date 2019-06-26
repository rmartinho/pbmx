pub trait PtrOptWrite<T> {
    unsafe fn opt_write(&self, t: T);
}

impl<T> PtrOptWrite<T> for *mut T {
    unsafe fn opt_write(&self, t: T) {
        if !self.is_null() {
            self.write(t);
        }
    }
}
