# jCrypto Examples

The example script are used as some sort of testing of the whole execution to show specific
scenarios.

## Setup

For basic test, just jcrypto and OpenSSL is needed. More advance scenarios with PKCS11 require
some specific installation to be done.

The jcrypto itself should be installed using following command:

```shell
mvn install
```

### PKCS11 server custom setup

This is the most advance setup with the custom builds for [OpenSSL](https://github.com/openssl/openssl/),
[pkcs11-engine](https://github.com/OpenSC/libp11),
[pkcs11-provider](https://github.com/latchset/pkcs11-provider/),
[nginx](https://github.com/nginx/nginx), [SoftHSMv2](https://github.com/softhsm/SoftHSMv2) and
[pkcs11-proxy](https://github.com/bukka/pkcs11-proxy). The components can be compiled in development
(debugging) mode or optimized production mode. Unless noted otherwise, all commands are run from
the directory of the source code (this can be downloaded either through git or directly from the
download location if provided). It should be also noted that it's possible to parallelize make run using
`-j` argument which is omitted here but can be safely added to speed the build up.

The configuration, compilation and installation requires following build tools to be installed:

- make
- gcc or clang
- cmake (for pkcs11-proxy)
- autotools (for libp11 and SoftHSMv2) - autoconf, automake, libtool
- meson which requires Python (for pkcs11-provider)

And to test the server, `curl` should also be installed.

#### OpenSSL

All other components depend on OpenSSL so it needs to be installed first. Let's consider that
OpenSSL (at least version 3.0.7) is going to be installed to `/usr/local/ssl` directory. Then it needs
to be configured in debug mode as following (prefix is optional as `/usr/local/ssl` is default so it could be
omitted and rpath is important just if multiple OpenSSL or used to correctly select the library without a need
to specify `LD_LIBRARY_PATH` environment variable).

```shell
CONFIG_OPTS="--strict-warnings" ./config shared -d --prefix=/usr/local/ssl -Wl,-rpath=/usr/local/ssl/lib64
```

The production configuration would just be as

```shell
./config shared --prefix=/usr/local/ssl -Wl,-rpath=/usr/local/ssl/lib64
```

To compile and install, following should be run

```shell
make
sudo make install
```

#### OpenSSL PKCS11 engine

To install libp11 (pcks11 engine), following commands should be run.

If the code comes from git, it needs to be bootstraped first using

```shell
./bootstrap
```

Then configure it for debug mode

```shell
OPENSSL_LIBS="-L/usr/local/ssl/lib64/ -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include" CFLAGS="-g -O0" ./configure
```

or for production

```shell
OPENSSL_LIBS="-L/usr/local/ssl/lib64/ -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include" ./configure
```

and then to compile and install it, following should be done

```shell
make
sudo make install
sudo cp src/.libs/pkcs11.so /usr/local/ssl/lib64/engines-3/pkcs11.so
```

#### OpenSSL PKCS11 provider

The PKCS11 provider is more advanced and needs to be configured using meson which requires Python.
Ideally it should be installed using pip to get the latest version.

Then the following setup command should be run for development mode:

```shell
PKG_CONFIG_PATH="/usr/local/ssl/lib64/pkgconfig" meson setup builddir
```

or for production, it should use release build type:

```shell
PKG_CONFIG_PATH="/usr/local/ssl/lib64/pkgconfig" meson setup builddir --buildtype=release
```

Then the following commands should be used to compile (`-v` is optional to see the commands) and
install it:

```shell
meson compile -C builddir -v
meson install -C builddir
```

#### SoftHSMv2

If source received from git, the autogen needs to be run:

```shell
./autogen.sh
```

The for debug (development) build, following configuration should be run:

```shell
PKG_CONFIG_LIBDIR=/usr/local/ssl/lib64/pkgconfig/ CFLAGS="-g -O0" CXXFLAGS="-g -O0" LDFLAGS="-L/usr/local/ssl/lib64 -Wl,-rpath,/usr/local/ssl/lib64"  ./configure --with-openssl=/usr/local/ssl
```

or for production

```shell
PKG_CONFIG_LIBDIR=/usr/local/ssl/lib64/pkgconfig/ LDFLAGS="-L/usr/local/ssl/lib64 -Wl,-rpath,/usr/local/ssl/lib64"  ./configure --with-openssl=/usr/local/ssl
```

Then standard compilation and installation should be done

````shell
make
sudo make install
````

#### pkcs11-proxy

First the build dir should be created or reset if already exists:

```shell
rm -rf build/
mkdir build
cd build
```

Then cmake should be run for debug build:

```shell
PKG_CONFIG_PATH=/usr/local/ssl/lib64/pkgconfig/ cmake -DENABLE_OPTIMIZATION=OFF ..
```

or for production build

```shell
PKG_CONFIG_PATH=/usr/local/ssl/lib64/pkgconfig/ cmake ..
```

Then standard compilation and installation should be done

````shell
make
sudo make install
````

#### nginx

The nginx configuration depends on used modules. Here only `http_ssl_module` is needed and included
but more modules can be added.

To configure nginx for development mode, following should be run

```shell
./auto/configure --with-http_ssl_module --with-cc-opt="-I/usr/local/ssl/include -O0" \
  --with-ld-opt="-L/usr/local/ssl/lib64 -Wl,-rpath=/usr/local/ssl/lib64" --with-debug
```

For production, following should be run:

```shell
./auto/configure --with-http_ssl_module --with-cc-opt="-I/usr/local/ssl/include" \
  --with-ld-opt="-L/usr/local/ssl/lib64 -Wl,-rpath=/usr/local/ssl/lib64"
```

Then standard compilation and installation should be done

````shell
make
sudo make install
````

## Usage

Most of the script can be just run after jcrypto is installed. The exception are server and other tests
discussed further.

### PKCS11 server tests

It is possible to use nginx in front of the server for more detailed PKCS11 testing. This can be run
either directly with SoftHSMv2 or pkcs11-proxy.

If there is custom OpenSSL build like described above, it might still be needed to set `LD_LIBRARY_PATH`
like:

```shell
export LD_LIBRARY_PATH=/usr/local/ssl/lib64
```

#### SoftHSMv2 usage

First start the server from examples/pkey directory using

```shell
./pkey-server-ec-pkcs11-test.sh
```

Optionally also start nginx from examples/ directory with either `pkcs11-provider` or `pkcs11-engine`
options like:

```shell
./run-nginx.sh pkcs11-provider
```

and then it is possible to send signing request from examples/ directory like this:

```shell
curl -X POST https://localhost:4443/pkey/sign --data-binary @pkey/in-pkey-data.txt -k
```

#### PKCS11-PROXY usage

It is possible to use pkcs11-proxy for nging and pkey-server.

The pkcs11-proxy daemon should be started first from the examples/ directory:

```shell
./run-pkcs11-proxy-daemon.sh  pkey-server
```

Then jcrypto pkey server test should be started from examples/pkey/ as

```shell
JCRYPTO_PKCS11_PROXY=1  ./pkey-server-ec-pkcs11-test.sh
```

And finally nginx should be started from example directory as

```shell
JCRYPTO_PKCS11_PROXY=1 ./run-nginx.sh pkcs11-provider
```

Then it is possible to send curl request from examples/ directory using:

```shell
curl -X POST https://localhost:4443/pkey/sign --data-binary @pkey/in-pkey-data.txt -k
```

Or with client certificate using:

```shell
curl --cert data/nginx_client_cert_bundle_ec_secp256r1.pem -X POST https://localhost:4443/pkey/sign --data-binary @pkey/in-pkey-data.txt -k
```

It is possible to also test the daemon restart. In such case the running daemon should be stopped
using CTRL+C and then started again but without recreating the keys:

```shell
PKCS11_KEYS_REUSE=1 ./run-pkcs11-proxy-daemon.sh  pkey-server
```
