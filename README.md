# act-nizkp
A Rust crate for a Non-Interactive Zero-Knowledge Authentication protocol in collaboration with the [Technical University of Munich (TUM)](https://www.tum.de/en/).

## Project compilation and Cross tool
* In this project we use the [cross tool](https://github.com/cross-rs/cross) to cross compile our crate for target `arm-unknown-linux-gnueabihf` and `armv7-unknown-linux-gnueabihf`. For example, inside the folder lib, run:\
`cross build --target=arm-unknown-linux-gnueabihf`
* The standard cargo tool could be used to build for Debian computers:\
`cargo build`

## Library
The crate code can be found at `./lib`

## Examples
Examples on using this crate can be found at `./examples`

## Security Analysis
Formal security analysis of this protocl using Tamarin-Prover can be found at `./tamarin_security_analysis`
