package walk

import (
	"context"
	"io"
	"io/fs"
	"iter"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
)

// FS recursively walks the squashed layers of an OCI image.
// Each Entry's Path() is a real path of file inside.
func Image(ctx context.Context, image *image.Image) iter.Seq2[Entry, error] {
	if image == nil {
		panic("image is nil")
	}

	return func(yield func(Entry, error) bool) {
		done := make(chan struct{})
		fn := func(path file.Path, node filenode.FileNode) error {
			if node.FileType != file.TypeRegular {
				return nil
			}
			if !yield(dentry{node: node, image: image}, nil) {
				close(done)
			}
			return nil
		}
		cond := filetree.WalkConditions{
			ShouldTerminate: func(_ file.Path, _ filenode.FileNode) bool {
				select {
				case <-ctx.Done():
					return true
				case <-done:
					return true
				default:
					return false
				}
			},
			ShouldVisit: func(_ file.Path, node filenode.FileNode) bool {
				return !node.IsLink()
			},
			ShouldContinueBranch: func(_ file.Path, node filenode.FileNode) bool {
				return !node.IsLink()
			},
			LinkOptions: nil,
		}
		_ = image.SquashedTree().Walk(fn, &cond)
	}
}

// dentry implements Entry for an image file node
// uses OpenReference and FileCatalog.Get for Open/Stat operations
type dentry struct {
	node  filenode.FileNode
	image *image.Image
}

func (e dentry) Path() string {
	return string(e.node.RealPath)
}

func (e dentry) Open() (io.ReadCloser, error) {
	return e.image.OpenReference(*e.node.Reference)
}

func (e dentry) Stat() (fs.FileInfo, error) {
	entry, err := e.image.FileCatalog.Get(*e.node.Reference)
	if err != nil {
		return nil, err
	}
	return entry.FileInfo, nil
}
