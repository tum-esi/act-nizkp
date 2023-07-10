# act-nizkp-examples
Example code for the Rust crate act-nizkp, in collaboration with the [Technical University of Munich (TUM)](https://www.tum.de/en/).

## Configuration
* To make sure that the tcp client and server examples works, you have to add the correct local IP address of your server. Please change them accordingly in files [tcp_client.rs](https://gitlabci.exxeta.com/firas.hamila/schnorr-nizk-examples/-/blob/master/src/tcp_client.rshttps://github.com/tum-esi/act-nizkp/blob/main/examples/src/tcp_client.rs) and [tcp_server.rs](https://gitlabci.exxeta.com/firas.hamila/schnorr-nizk-examples/-/blob/master/src/tcp_server.rshttps://github.com/tum-esi/act-nizkp/blob/main/examples/src/tcp_server.rs).
* You can keep the server running at one device and just try different combinations with the client on the other device. More info about how to use the client will be available when you run it.
* [main.rs](https://github.com/tum-esi/act-nizkp/blob/main/examples/src/main.rs) runs all the different part of the library after each other on the same hardware (no wireless connexion is involved).
* In all files [tcp_client.rs](https://gitlabci.exxeta.com/firas.hamila/schnorr-nizk-examples/-/blob/master/src/tcp_client.rshttps://github.com/tum-esi/act-nizkp/blob/main/examples/src/tcp_client.rs), [tcp_server.rs](https://gitlabci.exxeta.com/firas.hamila/schnorr-nizk-examples/-/blob/master/src/tcp_server.rshttps://github.com/tum-esi/act-nizkp/blob/main/examples/src/tcp_server.rs), and [main.rs](https://github.com/tum-esi/act-nizkp/blob/main/examples/src/main.rs), you can find a variable called `iterations` which you can set to `1` to run the examples only one time. Using `iterations=1000` will mimic the experiments we've done for our performance analysis.
* You have to keep the folder containing the library and this folder at the same place, or change the configuration in [Cargo.toml](https://github.com/tum-esi/act-nizkp/blob/main/examples/Cargo.toml).

## Project compilation and Cross tool
* In this project we use the [cross tool](https://github.com/cross-rs/cross) to cross compile our code for target `arm-unknown-linux-gnueabihf` and `armv7-unknown-linux-gnueabihf`. For example:\
`cross build --target=arm-unknown-linux-gnueabihf`
* To run the examples, we don't recommand using the [cross tool](https://github.com/cross-rs/cross), since you'll need to install some dependencies to make it run.\
You can send the executables to the devices (e.g. using SSH) and run them directly there. In our case, we used the [Raspberry Pi 3](https://www.raspberrypi.com/products/raspberry-pi-3-model-b-plus/) and the [Raspberry Pi Zero W](https://www.raspberrypi.com/products/raspberry-pi-zero-w/) with [Raspberry Pi OS Lite 32-bit](https://www.raspberrypi.com/software/operating-systems/).
* The standard cargo tool could be used to build for Debian computers:\
`cargo build`
* You can run the code on your Linux computer using the following command:\
`cargo run --bin tcp_server`
