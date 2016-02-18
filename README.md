WebMoney Signer
===============
[![Build Status](https://travis-ci.org/baibaratsky/go-wmsigner.svg)](https://travis-ci.org/baibaratsky/go-wmsigner)
[![GitHub license](https://img.shields.io/github/license/baibaratsky/go-wmsigner.svg)](https://github.com/baibaratsky/go-wmsigner)

Provides a convenient way to sign your requests to WebMoney API in Go with no need to run executables.



Installation
------------
```
go get github.com/baibaratsky/go-wmsigner
```

Usage
-----
```go
    package main

    import "github.com/baibaratsky/go-wmsigner"

    func main() {
        signer, err := wmsigner.New("wmid", "/full/path/to/the/key.kwm", "password")
        if err != nil {
            panic(err.Error())
        }

        signature, err := signer.Sign("Data to be signed")
        if err != nil {
            panic(err.Error())
        }
    }
```
