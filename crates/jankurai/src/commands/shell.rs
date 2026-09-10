use std::process::Command;

/// Preserve caller-selected tools without shell startup or loader injection.
/// This ordinary launcher does not confer supervised-execution authority.
pub(super) fn bash() -> Command {
    let mut command = Command::new("/bin/bash");
    command.args(["--noprofile", "--norc", "-p"]);
    for name in [
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ] {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"BASH_FUNC_") {
            command.env_remove(name);
        }
    }
    command
}
