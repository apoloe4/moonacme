// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "apoloe4/moonacme"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/apoloe4/moonacme"

license = "Apache-2.0"

keywords = [ "acme", "tls", "certificate", "rfc8555", "letsencrypt" ]

preferred_target = "wasm"

description = "Transport-neutral ACME certificate automation for MoonBit"
