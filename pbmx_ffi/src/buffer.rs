pub struct BufferFillPtr<T>(*mut T);

impl<T> BufferFillPtr<T> {
    pub fn new(ptr: *mut T) -> Option<BufferFillPtr<T>> {
        if ptr.is_null() {
            None
        } else {
            Some(BufferFillPtr(ptr))
        }
    }

    pub unsafe fn push(&mut self, t: T) {
        self.0.write(t);
        self.0 = self.0.offset(1);
    }
}
