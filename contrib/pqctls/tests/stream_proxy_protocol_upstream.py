#!/usr/bin/env python3

import argparse
import socket
from pathlib import Path


def recv_until(conn: socket.socket, marker: bytes, initial: bytes = b"") -> tuple[bytes, bytes]:
    data = bytearray(initial)
    while marker not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data.extend(chunk)

    payload = bytes(data)
    idx = payload.find(marker)
    if idx == -1:
        return payload, b""

    end = idx + len(marker)
    return payload[:end], payload[end:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--body", default="proxy protocol ok\n")
    args = parser.parse_args()

    output_path = Path(args.output)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.listen_host, args.listen_port))
        server.listen(1)

        while True:
            conn, _ = server.accept()
            with conn:
                proxy_header, remainder = recv_until(conn, b"\r\n")
                if not proxy_header.startswith(b"PROXY "):
                    continue

                request, _ = recv_until(conn, b"\r\n\r\n", remainder)
                if not request:
                    continue

                body = args.body.encode("utf-8")
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                conn.sendall(response)

                output_path.write_text(
                    proxy_header.decode("latin1") + "\n---\n" + request.decode("latin1"),
                    encoding="utf-8",
                )
                break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
