
install-tools:
	@echo installing tools && \
	@go install go.uber.org/mock/mockgen@latest \
	@go install github.com/swaggo/swag/cmd/swag@latest \
	@echo done

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