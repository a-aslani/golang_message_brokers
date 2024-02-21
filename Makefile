
install-tools:
	@echo installing tools && \
	@go install go.uber.org/mock/mockgen@latest \
	@go install github.com/swaggo/swag/cmd/swag@latest \
	@echo done

.PHONY: doc
doc: ## generate docs
	swag init -g ./cmd/swagger/swagger.go

.PHONY: run-swagger
run-swagger: ##run service locally
	go run main.go swagger

.PHONY: run-user
run-user: ##run service locally
	go run main.go user