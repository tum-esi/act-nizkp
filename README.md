# nizk_authentication
A NIZK Authentication protocol in Rust

## Cross tool
In this project we use the [cross tool](https://github.com/cross-rs/cross) to cross compile our code for target `armv7-unknown-linux-gnueabihf`.

The `Cross.toml` file provide the comfiguration for the cross compilation.
The `Dockerfile` contains the docker image used to compile for `armv7-unknown-linux-gnueabihf`.
