//! On Windows, the executable carries the logo as its icon (the taskbar,
//! the pinned tile, Explorer); elsewhere there is nothing to do.

fn main() {
    println!("cargo:rerun-if-changed=resources/masstin.ico");
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("resources/masstin.ico");
        res.set("ProductName", "masstin");
        res.set("FileDescription", "masstin — lateral movement tracker for anything");
        if let Err(e) = res.compile() {
            println!("cargo:warning=the executable keeps no icon: {}", e);
        }
    }
}
