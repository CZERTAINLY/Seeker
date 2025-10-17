package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	uploadPath  = "api/v1/bom"
	contentType = "application/vnd.cyclonedx+json; version = 1.6"
)

type BOMRepoUploader struct {
	requestURL *url.URL
	client     *http.Client
}

func NewBOMRepoUploader(serverURL string) (*BOMRepoUploader, error) {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")

	if parsedURL.Scheme == "" || parsedURL.Host == "" || parsedURL.Path != "" {
		return nil, errors.New("please define the server url with a scheme and without path, e.g. `http://some-url.com`")
	}

	parsedURL.Path = uploadPath
	q := parsedURL.Query()
	parsedURL.RawQuery = q.Encode()

	c := &BOMRepoUploader{
		requestURL: parsedURL,
		client:     &http.Client{},
	}

	return c, nil
}

func (c *BOMRepoUploader) Upload(ctx context.Context, raw []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.requestURL.String(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	createResp, err := c.decodeUploadResponse(resp)
	if err != nil {
		return err
	}
	slog.DebugContext(ctx, "BOM uploaded successfully.",
		slog.String("urn", createResp.SerialNumber),
		slog.Int("version", createResp.Version))

	return nil
}

type BOMCreateResponse struct {
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
}

func (c *BOMRepoUploader) decodeUploadResponse(resp *http.Response) (BOMCreateResponse, error) {
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return BOMCreateResponse{}, fmt.Errorf("failed to parse response content type header: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		if contentType != "application/json" {
			return BOMCreateResponse{}, fmt.Errorf("expected `application/json` content type, got: %s", contentType)
		}
		var bc BOMCreateResponse
		if err := json.NewDecoder(resp.Body).Decode(&bc); err != nil {
			return BOMCreateResponse{}, fmt.Errorf("decoding json response failed: %w", err)
		}
		if bc.SerialNumber == "" || bc.Version == 0 {
			return BOMCreateResponse{}, errors.New("received unexpected body")
		}
		return bc, nil

	// for now this is good enough, maybe later we'll decode the problem+json manually
	// for extra additional fields
	case http.StatusBadRequest:
		fallthrough
	case http.StatusConflict:
		fallthrough
	case http.StatusUnsupportedMediaType:
		if contentType != "application/problem+json" {
			return BOMCreateResponse{}, fmt.Errorf("expected `application/problem+json` content type, got: %s", contentType)
		}
		var problemDetail struct {
			Detail string `json:"detail"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&problemDetail); err != nil {
			return BOMCreateResponse{}, fmt.Errorf("decoding json response failed: %w", err)
		}
		return BOMCreateResponse{}, fmt.Errorf("status code: %d, detail: %s", resp.StatusCode, problemDetail.Detail)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return BOMCreateResponse{}, err
	}
	return BOMCreateResponse{}, fmt.Errorf("unknown error, status: %d, body: %s", resp.StatusCode, string(respBody))
}
