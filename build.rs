

fn main() {
    let liboping_path = match std::env::var_os("LIBOPING_PATH") {
        Some(path) => path,
        None => panic!("LIBOPING_PATH variable not set")
    };

    println!(r"cargo:rustc-link-search={}", liboping_path.to_str().unwrap())
}
