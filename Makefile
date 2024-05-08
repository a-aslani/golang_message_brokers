
install-tools:
	go install go.uber.org/mock/mockgen@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/cespare/reflex@latest
	go install github.com/rakyll/gotest@latest
	go install github.com/go-delve/delve/cmd/dlv@latest
	go install github.com/psampaz/go-mod-outdated@latest
	go install github.com/jondot/goweight@latest
	go install golang.org/x/tools/cmd/cover@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/sonatype-nexus-community/nancy@latest
	go mod tidy

generate:
	@echo running code generation
	@go generate ./...
	@echo done

.PHONY: up
up: ## run the application on docker
	@docker compose up --build -d

.PHONY: down
down: ## stop the application on docker
	@docker compose down

.PHONY: doc
doc: ## generate docs
	swag init -g ./cmd/swagger/swagger.go

.PHONY: run-swagger
run-swagger: ##run service locally
	go run main.go swagger

.PHONY: run-user
run-user: ##run service locally
	go run main.go user