curl -L https://www.openssl.org/source/openssl-1.1.0g.tar.gz | tar xz
cd openssl-1.1.0g
./config no-shared
make -j${nproc}
make install
cp libcrypto.a ../
