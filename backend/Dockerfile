# syntax=docker/dockerfile:1

FROM golang:1.21

ENV CONN "CONN"
ENV PORT "8080"
  
# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/engine/reference/builder/#copy
COPY * ./

RUN go install github.com/pressly/goose/v3/cmd/goose@latest
WORKDIR sql/schema
RUN goose postgres "${CONN}" up
RUN cd ../..
  
# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /thisweek-be

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/engine/reference/builder/#expose
EXPOSE ${PORT}

# Run
CMD ["/thisweek-be"]