package model

import "context"

type Uploader interface {
	Upload(ctx context.Context, raw []byte) error
}
