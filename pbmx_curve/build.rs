//! Generates a Ristretto rainbow table for small values

#![feature(iter_unfold)]

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, traits::Identity,
};
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    iter,
    path::Path,
};

const MAX_POINTS_MAPPED: usize = 2048;

fn main() {
    const G: &RistrettoPoint = &RISTRETTO_BASEPOINT_POINT;
    let id = RistrettoPoint::identity();

    let points = iter::successors(Some(id), |p| Some(p + G)).take(MAX_POINTS_MAPPED);

    let mut map = phf_codegen::Map::new();
    for (i, p) in points.enumerate() {
        map.entry(p.compress().0, &i.to_string());
    }

    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("curve_map.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());
    map.build(&mut file).unwrap();
    write!(&mut file, ";\n").unwrap();
}
