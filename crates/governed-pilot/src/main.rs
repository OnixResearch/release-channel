mod control;
mod input;
mod smoke;
mod witness;

use std::{env, path};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    anyhow::ensure!(
        args.len() == 4 && args[1] == "smoke",
        "usage: release-channel-governed-pilot smoke ABS_FIXTURE_ROOT ABS_FRESH_CONTROL_ROOT"
    );
    let fixtures = path::Path::new(&args[2]);
    let control = path::Path::new(&args[3]);
    anyhow::ensure!(
        fixtures.is_absolute() && control.is_absolute(),
        "absolute operator roots required"
    );
    smoke::run(fixtures, control)
}
