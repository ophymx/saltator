fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No system protoc required — use the vendored binary.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/internal.proto"], &["proto"])?;
    Ok(())
}
