fn main() {
    prost_build::compile_protos(
        &[
            "src/proto/core.proto",
            "src/proto/key.proto",
            "src/proto/chain.proto",
            "src/proto/proof.proto",
            "src/proto/private.proto",
        ],
        &["src/proto/"],
    )
    .unwrap();
}
