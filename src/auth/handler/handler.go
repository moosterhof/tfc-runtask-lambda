package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	//	"errors"
	// "io/ioutil"
	"log"
	//"net/http"
	//"strings"
	//	"time"

	"github.com/aws/aws-lambda-go/events"
	//	"github.com/aws/aws-lambda-go/lambda"
	//        "github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/open-policy-agent/opa/storage"
)

var (
	err      error
	store    storage.Store
	ctx      = context.Background()
)

type Response events.APIGatewayProxyResponse

// Handler - interface
type Handler interface {
	Run(ctx context.Context, event events.APIGatewayProxyRequest) (Response, error)
}

type lambdaHandler struct {
	hmacKey string
}

type LambdaResponse struct {
	Message string
}

type RequestBody struct {
	Payload_version               float64 `json:"payload_version"`
	Access_token                  string  `json:"access_token"`
	Task_result_id                string  `json:"task_result_id"`
	Task_result_enforcement_level string  `json:"task_result_enforcement_level"`
	Task_result_callback_url      string  `json:"task_result_callback_url"`
	Run_app_url                   string  `json:"run_app_url"`
	Run_id                        string  `json:"run_id"`
	Run_message                   string  `json:"run_message"`
	Run_created_at                string  `json:"run_created_at"`
	Run_created_by                string  `json:"run_created_by"`
	Workspace_id                  string  `json:"workspace_id"`
	Workspace_name                string  `json:"workspace_name"`
	Workspace_app_url             string  `json:"workspace_app_url"`
	Organization_name             string  `json:"organization_name"`
	Plan_json_api_url             string  `json:"plan_json_api_url"`
	Vcs_repo_url                  string  `json:"vcs_repo_url"`
	Vcs_branch                    string  `json:"vcs_branch"`
	Vcs_pull_request_url          string  `json:"vcs_pull_request_url"`
	Vcs_commit_url                string  `json:"vcs_commit_url"`
}

func (l lambdaHandler) Run(ctx context.Context, request events.APIGatewayProxyRequest) (Response, error) {

	log.Print("OPA Lambda starting")
	log.Print("Request body: ###", request.Body, "###")
	log.Print("Request headers: ###", request.Headers, "###")

	// this is the HMAC for the request, if available
	// case is like: X-Tfc-Event-Hook-Signature
	signature := request.Headers["X-Tfc-Event-Hook-Signature"]
	log.Print("HMAC header: ###", signature, "###")
	log.Print("HMAC key: ###", l.hmacKey, "###")
	actualMAC, _ := hex.DecodeString(signature)

	mac := hmac.New(sha512.New, []byte(l.hmacKey))
	mac.Write([]byte(request.Body))
	expectedMAC := mac.Sum(nil)
	match := hmac.Equal([]byte(actualMAC), expectedMAC)

	if match {
		log.Print("VALID MAC")
	} else {
		log.Print("INCORRECT MAC")
		return Response{Body: "incorrect MAC", StatusCode: 403}, nil
	}

	return buildResponse(LambdaResponse{Message: "Request Accepted"})
}

func buildResponse(lambdaResponse LambdaResponse) (Response, error) {
	response, err := json.Marshal(lambdaResponse)
	res := Response{
		StatusCode:      200,
		IsBase64Encoded: false,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":      "*",
			"Access-Control-Allow-Credentials": "true",
			"Cache-Control":                    "no-cache; no-store",
			"Content-Type":                     "application/json",
			"Content-Security-Policy":          "default-src self",
			"Strict-Transport-Security":        "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":           "nosniff",
			"X-XSS-Protection":                 "1; mode=block",
			"X-Frame-Options":                  "DENY",
		},
		Body: string(response),
	}
	return res, err
}

// NewLambdaHandler -
func NewLambdaHandler(
	hmacKey string,
) *lambdaHandler {
	return &lambdaHandler{
		hmacKey: hmacKey,
	}
}
