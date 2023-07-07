# nizk_authentication
A Rust library for a Non-Interactive Zero-Knowledge Authentication protocol in collaboration with the [Technical University of Munich (TUM)](https://www.tum.de/en/).

## Cross tool
In this project we use the [cross tool](https://github.com/cross-rs/cross) to cross compile our code for target `arm-unknown-linux-gnueabihf` and `armv7-unknown-linux-gnueabihf`.

## Library
The library code can be found at `./lib`

## Examples
Examples on using this library can be found at `./examples`

## Security Analysis
Formal security analysis of this protocl using Tamarin-Prover is avaialble at [this repo](https://github.com/tum-esi/act-nizk)
