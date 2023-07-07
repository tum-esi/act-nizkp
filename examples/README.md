# schnorr-nizk-examples
Examples of using the Rust library  [schnorr_nizk](https://gitlabci.exxeta.com/firas.hamila/nizk_authentication)

## Configuration
To make sure that the tcp client and server examples works, you have to add the correct local IP address of your server. Please change them accordingly in files [tcp_client.rs](https://gitlabci.exxeta.com/firas.hamila/schnorr-nizk-examples/-/blob/master/src/tcp_client.rs) and [tcp_server.rs](https://gitlabci.exxeta.com/firas.hamila/schnorr-nizk-examples/-/blob/master/src/tcp_server.rs). 

## Cross Compilation tool
In this project we use the [cross tool](https://github.com/cross-rs/cross) to cross compile our code for target `arm-unknown-linux-gnueabihf` and `armv7-unknown-linux-gnueabihf`.
