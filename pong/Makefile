all: docker-pong

pong: pong.go
	go build pong.go

.PHONY: docker-pong
docker-pong: pong
	docker build -t pong .
