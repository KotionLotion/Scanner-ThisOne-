# Scanner

A TCP port scanner with multiple features, written in Go.

## Features

- Custom target via `-target` flag
- Configurable port range via `-start-port` and `-end-port`
- Adjustable number of workers by `-workers` flag
- Scan summary showing open ports, time taken, and total ports scanned
- Timeout control through `-timeout` flag
- Banner grabbing for open ports
- Multiple target scanning via `-targets` flag (comma-separated)
- JSON output format in the `-json` flag
- Specific port scanning via `-ports` flag (comma-separated)

## How to Run

1. Basic Scan: ./port-scanner.exe -target scanme.nmap.org
2. Custom Port: ./port-scanner.exe -target example.com -start-port 20 -end-port 80
3. Multiple/Specific: ./port-scanner.exe -targets scanme.nmap.org,example.com -ports 22,80,443,8080
4. Json: ./port-scanner.exe -target scanme.nmap.org -json

## Video Link:

 - Video explaining code: 
