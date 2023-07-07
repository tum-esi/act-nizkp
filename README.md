# nizk_authentication
A Rust library for a Non-Interactive Zero-Knowledge Authentication protocol in collaboration with the [Associate Professorship of Embedded Systems and Internet of Things](https://www.ce.cit.tum.de/en/esi/home/) at Technical University of Munich (TUM)

## Cross tool
In this project, we use the [cross tool](https://github.com/cross-rs/cross) to cross-compile our code for target `arm-unknown-linux-gnueabihf` and `armv7-unknown-linux-gnueabihf`.

## Library
The library code can be found at `./lib`

## Examples
Examples of using this library can be found at `./examples`

## Security Analysis
Formal security analysis of this protocol using Tamarin-Prover
