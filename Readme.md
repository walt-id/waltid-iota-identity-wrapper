# walt.id IOTA identity wrapper

This is a simple RUST library, wrapping the [IOTA identity framework](https://wiki.iota.org/identity.rs/introduction), exposing a plain C interface, that can be loaded via dynamic library loading in most languages such as Java, etc.

The library is used by the [walt.id SSIKit](https://github.com/walt-id/waltid-ssikit), to integrate IOTA DID management and resolution.

Currently the only supported actions are:

* Did creation and registration on the IOTA tangle
* Did resolution via the IOTA tangle

## Build

To build the library, you need to have a RUST build environment on your development workstation.

### RUST build environment

Set up the RUST build environment, e.g. using rustup:

[RUST installation](https://www.rust-lang.org/tools/install)

[rustup.rs](https://rustup.rs/#)

Or using [another installation method](https://forge.rust-lang.org/infra/other-installation-methods.html) depending on your operating system.

### Release build

To build the library with the release compiler configuration, execute the cargo build command like so:

`cargo build --release`

The command automatically loads all dependencies and builds the library.
The build output can be found here:

_Linux:_

`./target/release/libwaltid_iota_identity_wrapper.so`

_Note: the library file name may look different on operating systems other than Linux_

## SSIKit integration

For the integration with the [SSI Kit](https://github.com/walt-id/waltid-ssikit), make sure the wrapper library is in the library search path of your operating system.
On **Windows**, this is usually the working directory, on **Linux** you may need to set the `LD_LIBRARY_PATH` environment variable:

`export LD_LIBRARY_PATH=/path/to/waltid-iota-identity-wrapper/target/release`

Then run the SSI Kit did creation or resolution commands, e.g.:

`ssikit did create -m iota`

`ssikit did resolve -d did:iota:...`


