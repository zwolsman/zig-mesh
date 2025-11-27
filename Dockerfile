FROM gcr.io/distroless/static-debian12:latest-amd64
COPY zig-out/bin/ /app

WORKDIR /app

ENTRYPOINT [ "/app/zigio_mesh" ]
CMD ["-l", "0"]