FROM golang:1.26.5-alpine AS builder
# Build context must be go/ (the parent module), not this directory --
# examples/petstore/go.mod has `replace github.com/keyorixhq/keyorix-sdks/go
# => ../..` (the SDK isn't published/tagged yet), so the parent module's
# actual source must be present in the build context for that replace to
# resolve. See docker-compose.yml's context: ../.. for the working invocation.
WORKDIR /app
COPY . .
WORKDIR /app/examples/petstore
RUN go mod download
RUN go build -o petstore .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && \
    addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/examples/petstore/petstore .
USER appuser
EXPOSE 3001
CMD ["./petstore"]
