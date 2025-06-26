may need to build with static crt 
cargo rustc --release --bin nt_unhooker -- -C target-feature=+crt-static
