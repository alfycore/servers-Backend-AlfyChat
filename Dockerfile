FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/service .

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=build /out/service /app/service
COPY public /app/public
EXPOSE 3005
ENTRYPOINT ["/app/service"]
