sshauth: generated.go cmd/sshauth.go
	go build -o sshauth cmd/sshauth.go

generated.go: schema.graphql queries.graphql
	go run github.com/Khan/genqlient
