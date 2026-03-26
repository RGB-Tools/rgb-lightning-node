fn main() {
    #[cfg(feature = "uniffi")]
    uniffi::generate_scaffolding("bindings/rgb_lightning_node.udl").expect(
        "failed to generate UniFFI scaffolding from bindings/rgb_lightning_node.udl; \
         verify the UDL syntax and that the bindings path exists",
    );
}
