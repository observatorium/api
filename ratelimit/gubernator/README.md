# [Gubernator](https://github.com/mailgun/gubernator)

[Gubernator](https://github.com/mailgun/gubernator) is a distributed, high performance, cloud native and stateless rate limiting service.

We generate gRPC client code (`gubernator.pb.go`) using `gobernator.proto` which is a file directly download from the project repository.
You can find the 3rd party dependencies for proto generation under `proto` directory. 
To update or re-generate please use `make proto`.

