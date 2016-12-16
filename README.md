
Good morning!

To build this project with your host tools you can simply do:

```
$ make
```

This will produce a few example binaries as well as ready to static link libs

 1. thttp-example1
 2. thttp-example1-tls
 3. trest-example1
 4. trest-example1-tls


These test binaries can have their runtime behaviour configured/adjusted using the following
environment variables:

 1. CAFILE: the root certificate chain you want the tls client to use for validating the server
    - you can produce this inside pantahub-base/pki directory. Read the README.md in that project
      for more details.
 2. PANTAHUB_HOST: hostname your clients should call to; default is localhost
 2. PANTAHUB_PORT: port your clients should call to; default is 12365 for plain and 12366 for TLS

