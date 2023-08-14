// Package account provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.13.4 DO NOT EDIT.
package account

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
)

// ErrorResponse defines model for ErrorResponse.
type ErrorResponse struct {
	Error string `json:"error"`
}

// N401 defines model for 401.
type N401 = ErrorResponse

// N404 defines model for 404.
type N404 = ErrorResponse

// N500 defines model for 500.
type N500 = ErrorResponse

// PostUserSigninJSONBody defines parameters for PostUserSignin.
type PostUserSigninJSONBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// PostUserSignupJSONBody defines parameters for PostUserSignup.
type PostUserSignupJSONBody struct {
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Password  string `json:"password"`
	Phone     int    `json:"phone"`
}

// PostUserSigninJSONRequestBody defines body for PostUserSignin for application/json ContentType.
type PostUserSigninJSONRequestBody PostUserSigninJSONBody

// PostUserSignupJSONRequestBody defines body for PostUserSignup for application/json ContentType.
type PostUserSignupJSONRequestBody PostUserSignupJSONBody

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// PostUserSigninWithBody request with any body
	PostUserSigninWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostUserSignin(ctx context.Context, body PostUserSigninJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)

	// PostUserSignupWithBody request with any body
	PostUserSignupWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error)

	PostUserSignup(ctx context.Context, body PostUserSignupJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) PostUserSigninWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostUserSigninRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostUserSignin(ctx context.Context, body PostUserSigninJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostUserSigninRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostUserSignupWithBody(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostUserSignupRequestWithBody(c.Server, contentType, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) PostUserSignup(ctx context.Context, body PostUserSignupJSONRequestBody, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewPostUserSignupRequest(c.Server, body)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewPostUserSigninRequest calls the generic PostUserSignin builder with application/json body
func NewPostUserSigninRequest(server string, body PostUserSigninJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostUserSigninRequestWithBody(server, "application/json", bodyReader)
}

// NewPostUserSigninRequestWithBody generates requests for PostUserSignin with any type of body
func NewPostUserSigninRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/user/signin")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

// NewPostUserSignupRequest calls the generic PostUserSignup builder with application/json body
func NewPostUserSignupRequest(server string, body PostUserSignupJSONRequestBody) (*http.Request, error) {
	var bodyReader io.Reader
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	bodyReader = bytes.NewReader(buf)
	return NewPostUserSignupRequestWithBody(server, "application/json", bodyReader)
}

// NewPostUserSignupRequestWithBody generates requests for PostUserSignup with any type of body
func NewPostUserSignupRequestWithBody(server string, contentType string, body io.Reader) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/user/signup")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", queryURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// PostUserSigninWithBodyWithResponse request with any body
	PostUserSigninWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostUserSigninResponse, error)

	PostUserSigninWithResponse(ctx context.Context, body PostUserSigninJSONRequestBody, reqEditors ...RequestEditorFn) (*PostUserSigninResponse, error)

	// PostUserSignupWithBodyWithResponse request with any body
	PostUserSignupWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostUserSignupResponse, error)

	PostUserSignupWithResponse(ctx context.Context, body PostUserSignupJSONRequestBody, reqEditors ...RequestEditorFn) (*PostUserSignupResponse, error)
}

type PostUserSigninResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *struct {
		Token string `json:"token"`
	}
	JSON401 *N401
	JSON404 *N404
	JSON500 *N500
}

// Status returns HTTPResponse.Status
func (r PostUserSigninResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostUserSigninResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type PostUserSignupResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *struct {
		Token string `json:"token"`
	}
	JSON401 *N401
	JSON404 *N404
	JSON500 *N500
}

// Status returns HTTPResponse.Status
func (r PostUserSignupResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r PostUserSignupResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// PostUserSigninWithBodyWithResponse request with arbitrary body returning *PostUserSigninResponse
func (c *ClientWithResponses) PostUserSigninWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostUserSigninResponse, error) {
	rsp, err := c.PostUserSigninWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostUserSigninResponse(rsp)
}

func (c *ClientWithResponses) PostUserSigninWithResponse(ctx context.Context, body PostUserSigninJSONRequestBody, reqEditors ...RequestEditorFn) (*PostUserSigninResponse, error) {
	rsp, err := c.PostUserSignin(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostUserSigninResponse(rsp)
}

// PostUserSignupWithBodyWithResponse request with arbitrary body returning *PostUserSignupResponse
func (c *ClientWithResponses) PostUserSignupWithBodyWithResponse(ctx context.Context, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*PostUserSignupResponse, error) {
	rsp, err := c.PostUserSignupWithBody(ctx, contentType, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostUserSignupResponse(rsp)
}

func (c *ClientWithResponses) PostUserSignupWithResponse(ctx context.Context, body PostUserSignupJSONRequestBody, reqEditors ...RequestEditorFn) (*PostUserSignupResponse, error) {
	rsp, err := c.PostUserSignup(ctx, body, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParsePostUserSignupResponse(rsp)
}

// ParsePostUserSigninResponse parses an HTTP response from a PostUserSigninWithResponse call
func ParsePostUserSigninResponse(rsp *http.Response) (*PostUserSigninResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &PostUserSigninResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 401:
		var dest N401
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON401 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest N404
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest N500
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParsePostUserSignupResponse parses an HTTP response from a PostUserSignupWithResponse call
func ParsePostUserSignupResponse(rsp *http.Response) (*PostUserSignupResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &PostUserSignupResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 401:
		var dest N401
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON401 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 404:
		var dest N404
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON404 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest N500
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Sign in to an existing account
	// (POST /user/signin)
	PostUserSignin(ctx echo.Context) error
	// Sign up for a new account
	// (POST /user/signup)
	PostUserSignup(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// PostUserSignin converts echo context to params.
func (w *ServerInterfaceWrapper) PostUserSignin(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.PostUserSignin(ctx)
	return err
}

// PostUserSignup converts echo context to params.
func (w *ServerInterfaceWrapper) PostUserSignup(ctx echo.Context) error {
	var err error

	// Invoke the callback with all the unmarshaled arguments
	err = w.Handler.PostUserSignup(ctx)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface) {
	RegisterHandlersWithBaseURL(router, si, "")
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.POST(baseURL+"/user/signin", wrapper.PostUserSignin)
	router.POST(baseURL+"/user/signup", wrapper.PostUserSignup)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"H4sIAAAAAAAC/+xUTW/TQBD9K6uBo6lTCBffQKJSQSqItuIAHLbrSbytPbvMjhtClP+OZp3WKS1pe+kB",
	"cUq88+bN15tZgQtdDIQkCaoVMKYYKGH+mE729ccFEiTRvzbG1jsrPlB5ngLpW3INdlb/PWecQQXPypGz",
	"HKypfMcc+POGHdbrdQE1Jsc+KhlUcEq2lyaw/4U1rAuYTqZPF/woiDkIPeXIryeTp4t8SIJMtjXHyJfI",
	"JjuA4jYUGuEmS7WCyCEiix/mhNmnWoEsI0IFSdjTPJMw/ug9Yw3V1w3se3EFC2fn6GSIha5nL8tjjTmQ",
	"nqFl5De9NOPXQeDOClTw/ssJbDJUpsEK18yNSByK9TQL6n+z6JPGJ2OjN7ZtwyIZadC41iOJkWC8tsQ6",
	"MQsvTbadWbowCfnSO1REG+aeCuMYraARtpSsU+6kVmnQ8+BjnQs9yd430uS8tJrd5hEKuEROQ0b7e5O9",
	"iQ4/RCQbPVTwKj8VEK00uSNln5DL5OfkswJiSFkdOoqsjcMaKvgUkpwm5OMBN4wAk7wN9fJRsvpjxp31",
	"7R0z1vxSWgSuHyCAzLHlcYcWbu9lQjY1ivVtMrPAZmjA3HjSZlsy+NMn0ZexsWNU4R5zGlt35eUjF+xm",
	"JyRcIN1f7AB7SIUfP5gXJpepFwhJNJOrI7T/tw2/rqhU0Hiw7sNOt07MbqyC8nL2XWd5CRWopnb0XcGj",
	"SPv4MJH28QlEOvOc5Mh2eKe1tTuMO/RdQGwCbbvp7Zgj31LDGH8r2pV78X8z/onN6GMegzWEi62lWK9/",
	"BwAA//8vjKJp5ggAAA==",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}