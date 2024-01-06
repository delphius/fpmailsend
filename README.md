# fpmailsend

Collection of working utilities and modules for sending a simple email message in [Free Pascal](https://www.freepascal.org/)

Due to the lack of a built-in utility for sending e-mail messages in the modules included in fpc, I decided to collect in one place the maximum number of ways to implement this functionality, both with the help of built-in capabilities of fpc and using third-party libraries

[tlsmail](https://github.com/delphius/fpmailsend/tree/main/native/tlsmail) - native free pascal tls 1.3 mail send thru 465 port without any external library (for test, tested with gmail under Windows and Linux)

Any help and guidance on new ways to implement this function is welcome, the ultimate goal is to include the native cross platform function of sending a simple email message thru smtp with/without ssl as part of the [fcl-net](https://wiki.freepascal.org/fcl-net) package
