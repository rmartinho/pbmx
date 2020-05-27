use crate::error::Result;
use std::{fs::OpenOptions, io::Write, path::Path};

pub fn write_new<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.as_ref())?
        .write_all(contents.as_ref())?;
    Ok(())
}
