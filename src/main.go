package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var (
	err      error
	compiler *ast.Compiler
	store    storage.Store
	ctx      = context.Background()
)

func init() {

	policyData, err := loader.All([]string{"data"})
	if err != nil {
		log.Fatalf("Failed to load bundle from disk: %v", err)
	}

	// Compile the module. The keys are used as identifiers in error messages.
	compiler, err = policyData.Compiler()
	if err != nil {
		log.Fatalf("Failed to compile policies in bundle: %v", err)
	}

	store, err = policyData.Store()
	if err != nil {
		log.Fatalf("Failed to create storage from bundle: %v", err)
	}
}

func handler(request events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {

	usergroup := request.Headers["usergroup"]
	resource := request.Headers["resource"]

	fmt.Println("usergroup is = ", usergroup)
	fmt.Println("resource is = ", resource)

	// Run evaluation.
	start := time.Now()
	// Create a new query that uses the compiled policy from above.
	rego := rego.New(
		rego.Query("data.opablog.allow"),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(
			map[string]interface{}{
				"Usergroup": usergroup,
				"Resource":  resource,
			}),
	)

	elapsed := time.Since(start)
	fmt.Println("Query initiation  took ", elapsed)
	start_eval := time.Now()
	// Run evaluation.
	rs, err := rego.Eval(ctx)
	elapsed_eval := time.Since(start_eval)
	fmt.Println("Evaluation  took ", elapsed_eval)

	if err != nil {
		// Handle error.
	}

	fmt.Println("Result of query evaluation is = ", rs[0].Expressions[0].Value)
	if rs[0].Expressions[0].Value == true {
		return generatePolicy("user", "Allow", request.MethodArn), nil
	} else {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("Unauthorized")
	}

}

func main() {
	lambda.Start(handler)
}

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}

	return authResponse
}

func TFCget(url string) {

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(string(body))

	return
}


// This POSTs the output back to TFC
func tfcCallback(message string, url string) {

	bytesRepresentation, err := json.Marshal(message)
	if err != nil {
		log.Fatalln(err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(bytesRepresentation))
	if err != nil {
		log.Fatalln(err)
	}

	var result map[string]interface{}

	json.NewDecoder(resp.Body).Decode(&result)

	log.Println(result)
	log.Println(result["data"])
}
