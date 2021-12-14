fn main() {
    let mut config = cmake::Config::new("unicorn");
    config.configure_arg("-DUNICORN_ARCH=X86");
    config.configure_arg("-DUNICORN_BUILD_SHARED=OFF");
    config.configure_arg("-DBUILD_SHARED_LIBS=OFF");

    #[cfg(target_env = "msvc")]
    if !std::env::var("CMAKE_GENERATOR").is_ok() {
        config.generator("Ninja");
    }

    let target = config.build_target("unicorn");
    println!(
        "cargo:rustc-link-search=native={}",
        target.build().join("build").display()
    );
    println!("cargo:rustc-link-lib=unicorn");
    println!("cargo:rustc-link-lib=unicorn-common");
    println!("cargo:rustc-link-lib=x86_64-softmmu");
}
