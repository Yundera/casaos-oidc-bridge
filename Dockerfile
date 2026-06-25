FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY assets/ ./assets/
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -o /bridge .

FROM gcr.io/distroless/static-debian12
COPY --from=build /bridge /bridge
EXPOSE 8089
ENTRYPOINT ["/bridge"]
