# Build a static fpcheck binary, then ship it in a scratch image.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/fpcheck .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fpcheck /usr/local/bin/fpcheck
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/fpcheck"]
CMD ["serve", "--addr", ":8443"]
