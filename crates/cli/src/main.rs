//! Native binary entry point. Thin wrapper -- the work is in `phylaxis_cli::run`.

fn main() {
    let code = phylaxis_cli::run(std::env::args().collect());
    std::process::exit(code);
}
