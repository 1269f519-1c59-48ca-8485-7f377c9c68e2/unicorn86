fn main() {
    let mut config = cmake::Config::new("unicorn");
    config.configure_arg("-DUNICORN_ARCH=X86");
    config.configure_arg("-DUNICORN_BUILD_SHARED=OFF");
    config.configure_arg("-DBUILD_SHARED_LIBS=OFF");
    config.configure_arg("-DUNICORN_BUILD_TESTS=OFF");
    config.configure_arg("-DUNICORN_INSTALL=OFF");
    config.configure_arg("-DCMAKE_BUILD_TYPE=Release");

    #[cfg(target_env = "msvc")]
    {
        if !std::env::var("CMAKE_GENERATOR").is_ok() {
            config.generator("Ninja");
        }
        println!("cargo:rustc-link-arg=/FORCE:MULTIPLE");
    }

    let target = config.build_target("unicorn");
    println!(
        "cargo:rustc-link-search=native={}",
        target.build().join("build").display()
    );
    println!("cargo:rustc-link-lib=static=unicorn-common");
    println!("cargo:rustc-link-lib=static=x86_64-softmmu");
    println!("cargo:rustc-link-lib=static=unicorn-static");
}
