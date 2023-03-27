# nizk_authentication
A Rust library for a Non-Interactive Zero-Knowledge Authentication protocol in Rust

## Cross tool
In this project we use the [cross tool](https://github.com/cross-rs/cross) to cross compile our code for target `armv7-unknown-linux-gnueabihf`.

The `Cross.toml` file provide the comfiguration for the cross compilation.
The `Dockerfile` contains the docker image used to compile for `armv7-unknown-linux-gnueabihf`.

## Known Issues
When running the code using the cross toll, the secret key management system won't work probably. However, when built using cross and run directly on a raspberry pi 3 it would work. Tested only for raspberry pi 3 and linux computers.