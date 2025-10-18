package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pd "github.com/kodeart/go-problem/v2"

	"github.com/stretchr/testify/require"
)

func TestNewBOMRepoUploaderFunc(t *testing.T) {

	testCases := map[string]struct {
		serverURL string
		wantErr   bool
	}{
		"success http no trailing slash":          {serverURL: "http://some-server.com", wantErr: false},
		"success http trailing slash":             {serverURL: "http://some-server.com/", wantErr: false},
		"success http port no trailing slash":     {serverURL: "http://some-server.com:8080", wantErr: false},
		"success http port trailing slash":        {serverURL: "https://some-server-com:8090/", wantErr: false},
		"success https no trailing slash":         {serverURL: "https://some-server.com", wantErr: false},
		"success https trailing slash":            {serverURL: "https://some-server.com/", wantErr: false},
		"success https port no trailing slash":    {serverURL: "https://some-server.com:8080", wantErr: false},
		"success https port trailing slash":       {serverURL: "https://some-server-com:8090/", wantErr: false},
		"fail missing schema":                     {serverURL: "some-server.com", wantErr: true},
		"fail missing schema trailing slash":      {serverURL: "some-server.com/", wantErr: true},
		"fail missing schema port":                {serverURL: "some-server.com:8080", wantErr: true},
		"fail missing schema port trailing slash": {serverURL: "some-server.com:8090/", wantErr: true},
		"fail http path set":                      {serverURL: "http://some-server.com/some/path", wantErr: true},
		"fail http port path set":                 {serverURL: "http://some-server.com:8080/some/path", wantErr: true},
		"faail https path set":                    {serverURL: "https://some-server.com/some/path", wantErr: true},
		"fail httos port path set":                {serverURL: "https://some-server.com:8080/some/path", wantErr: true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			u, err := NewBOMRepoUploader(tc.serverURL)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, u)
			}
		})
	}
}

func TestDecodeUploadResponse(t *testing.T) {

	u, err := NewBOMRepoUploader("http://some-server.com")
	require.NoError(t, err)
	require.NotNil(t, u)

	testCases := map[string]struct {
		resp     func() *http.Response
		wantErr  bool
		expected BOMCreateResponse
	}{
		"201 application/json expected body": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusCreated,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"version":1,"serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}`)),
				}
				resp.Header.Set("Content-Type", "application/json")
				return resp
			},
			wantErr: false,
			expected: BOMCreateResponse{
				SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
				Version:      1,
			},
		},
		"201 application/json unexpected body": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusCreated,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"return":{"version":1,"serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}}`)),
				}
				resp.Header.Set("Content-Type", "application/json")
				return resp
			},
			wantErr: true,
		},
		"201 application/json unexpected body #2": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusCreated,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`just some string`)),
				}
				resp.Header.Set("Content-Type", "application/json")
				return resp
			},
			wantErr: true,
		},
		"201 unexpected content type": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusCreated,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"response":"version, urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}`)),
				}
				resp.Header.Set("Content-Type", "plain/text")
				return resp
			},
			wantErr: true,
		},
		// 400
		"400 application/problem+json expected body": {
			resp: func() *http.Response {
				b, err := json.Marshal(pd.Problem{
					Status: http.StatusBadRequest,
					Detail: "some detail",
				})
				if err != nil {
					t.Fatalf("`json.Marshal()` failed: %s", err)
				}

				resp := &http.Response{
					StatusCode: http.StatusBadRequest,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(b))),
				}
				resp.Header.Set("Content-Type", "application/problem+json")
				return resp
			},
			wantErr: true,
		},
		"400 bad content-type expected body": {
			resp: func() *http.Response {
				b, err := json.Marshal(pd.Problem{
					Status: http.StatusBadRequest,
					Detail: "some detail",
				})
				if err != nil {
					t.Fatalf("`json.Marshal()` failed: %s", err)
				}

				resp := &http.Response{
					StatusCode: http.StatusBadRequest,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(b))),
				}
				resp.Header.Set("Content-Type", "application/json")
				return resp
			},
			wantErr: true,
		},
		"400 application/problem+json unexpected body": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusBadRequest,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`abrakadabra`)),
				}
				resp.Header.Set("Content-Type", "application/problem+json")
				return resp
			},
			wantErr: true,
		},
		// 409
		"409 application/problem+json expected body": {
			resp: func() *http.Response {
				b, err := json.Marshal(pd.Problem{
					Status: http.StatusConflict,
					Detail: "some detail",
				})
				if err != nil {
					t.Fatalf("`json.Marshal()` failed: %s", err)
				}

				resp := &http.Response{
					StatusCode: http.StatusConflict,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(b))),
				}
				resp.Header.Set("Content-Type", "application/problem+json")
				return resp
			},
			wantErr: true,
		},
		"409 bad content-type expected body": {
			resp: func() *http.Response {
				b, err := json.Marshal(pd.Problem{
					Status: http.StatusConflict,
					Detail: "some detail",
				})
				if err != nil {
					t.Fatalf("`json.Marshal()` failed: %s", err)
				}

				resp := &http.Response{
					StatusCode: http.StatusConflict,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(b))),
				}
				resp.Header.Set("Content-Type", "application/json")
				return resp
			},
			wantErr: true,
		},
		"409 application/problem+json unexpected body": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusConflict,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`abrakadabra`)),
				}
				resp.Header.Set("Content-Type", "application/problem+json")
				return resp
			},
			wantErr: true,
		},
		// 415
		"415 application/problem+json expected body": {
			resp: func() *http.Response {
				b, err := json.Marshal(pd.Problem{
					Status: http.StatusUnsupportedMediaType,
					Detail: "some detail",
				})
				if err != nil {
					t.Fatalf("`json.Marshal()` failed: %s", err)
				}

				resp := &http.Response{
					StatusCode: http.StatusUnsupportedMediaType,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(b))),
				}
				resp.Header.Set("Content-Type", "application/problem+json")
				return resp
			},
			wantErr: true,
		},
		"415 bad content-type expected body": {
			resp: func() *http.Response {
				b, err := json.Marshal(pd.Problem{
					Status: http.StatusUnsupportedMediaType,
					Detail: "some detail",
				})
				if err != nil {
					t.Fatalf("`json.Marshal()` failed: %s", err)
				}

				resp := &http.Response{
					StatusCode: http.StatusUnsupportedMediaType,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(string(b))),
				}
				resp.Header.Set("Content-Type", "application/json")
				return resp
			},
			wantErr: true,
		},
		"415 application/problem+json unexpected body": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusUnsupportedMediaType,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`abrakadabra`)),
				}
				resp.Header.Set("Content-Type", "application/problem+json")
				return resp
			},
			wantErr: true,
		},
		"unexpected status code": {
			resp: func() *http.Response {
				resp := &http.Response{
					StatusCode: http.StatusTeapot,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`simsalabim`)),
				}
				resp.Header.Set("Content-Type", "application/octet-stream")
				return resp
			},
			wantErr: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			r, err := u.decodeUploadResponse(tc.resp())
			if tc.wantErr {
				require.Error(t, err)
				t.Log(err)
			} else {
				require.NoError(t, err)
				require.EqualValues(t, tc.expected, r)
			}
		})
	}
}

func TestBOMRepoUploadBadServerURLFunc(t *testing.T) {
	u, err := NewBOMRepoUploader("http://does-not-exist.yet")
	require.NoError(t, err)
	require.NotNil(t, u)

	err = u.Upload(context.Background(), []byte(`abcd`))
	require.Error(t, err)
}

func TestBOMRepoUploadFunc(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	testCases := map[string]struct {
		setup   func() (*httptest.Server, func())
		wantErr bool
	}{
		"201 application/json expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"version":1,"serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}`))
				}))
				return ts, ts.Close
			},
			wantErr: false,
		},
		"201 application/json unexpected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"return":{"version":1,"serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}}`))
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"201 application/json unexpected body #2": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`string that is definitely not json`))
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"201 unexpected content type": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "plain/text")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"version":1,"urn":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"}`))
				}))
				return ts, ts.Close
			},

			wantErr: true,
		},

		"400 application/problem+json expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					p := pd.Problem{
						Status: http.StatusBadRequest,
						Detail: "some detail",
					}
					p.JSON(w)
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"400 bad content-type expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, err := json.Marshal(pd.Problem{
						Status: http.StatusBadRequest,
						Detail: "some detail",
					})
					if err != nil {
						t.Fatalf("`json.Marshal()` failed: %s", err)
					}
					w.Header().Set("Content-Type", "plain/text")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write(b)
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"400 application/problem+json unexpected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`not a json string`))
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"409 application/problem+json expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					p := pd.Problem{
						Status: http.StatusConflict,
						Detail: "some detail",
					}
					p.JSON(w)
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"409 bad content-type expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, err := json.Marshal(pd.Problem{
						Status: http.StatusConflict,
						Detail: "some detail",
					})
					if err != nil {
						t.Fatalf("`json.Marshal()` failed: %s", err)
					}
					w.Header().Set("Content-Type", "plain/text")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write(b)
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"409 application/problem+json unexpected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`not a json string`))
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"415 application/problem+json expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					p := pd.Problem{
						Status: http.StatusUnsupportedMediaType,
						Detail: "some detail",
					}
					p.JSON(w)
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"415 bad content-type expected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, err := json.Marshal(pd.Problem{
						Status: http.StatusUnsupportedMediaType,
						Detail: "some detail",
					})
					if err != nil {
						t.Fatalf("`json.Marshal()` failed: %s", err)
					}
					w.Header().Set("Content-Type", "plain/text")
					w.WriteHeader(http.StatusUnsupportedMediaType)
					_, _ = w.Write(b)
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
		"415 application/problem+json unexpected body": {
			setup: func() (*httptest.Server, func()) {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusUnsupportedMediaType)
					_, _ = w.Write([]byte(`not a json string`))
				}))
				return ts, ts.Close
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {

			s, closeFunc := tc.setup()
			defer closeFunc()

			u, err := NewBOMRepoUploader(s.URL)
			require.NoError(t, err)
			require.NotNil(t, u)

			err = u.Upload(context.Background(), []byte(`abcd`))
			if tc.wantErr {
				require.Error(t, err)
				t.Log(err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
