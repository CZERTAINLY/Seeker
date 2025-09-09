package walk

import (
	"context"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
)

// FS returns an iterator over a filesystem - it returns an iterator for every
// regular file or an error it visits.
// It DOES NOT follow symlink. It DOES NOT open a file. Visits are done if all
// files are visited or when the context is canceled.
func FS(ctx context.Context, root *os.Root) iter.Seq2[Entry, error] {
	if root == nil {
		panic("root is nil")
	}
	return func(yield func(Entry, error) bool) {
		_ = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			var entry = fsEntry{
				root: root,
				path: path,
			}
			var yieldErr error
			if err != nil {
				yieldErr = err
			} else {
				info, err := d.Info()
				if err != nil {
					entry.infoErr = err
					yieldErr = err
				} else {
					if !info.Mode().IsRegular() {
						return nil
					}
					entry.info = info
					yieldErr = nil
				}
			}

			if !yield(entry, yieldErr) {
				return fs.SkipAll
			}

			return nil
		})
	}
}

// fsEntry implements Entry for a filesystem
// it uses root.Open to open the file
type fsEntry struct {
	root    *os.Root
	path    string
	info    fs.FileInfo
	infoErr error
}

// returns the absolute path to the file
func (e fsEntry) Path() string {
	return filepath.Join(e.root.Name(), e.path)
}

func (e fsEntry) Open() (io.ReadCloser, error) {
	if e.infoErr != nil {
		return nil, e.infoErr
	}
	return e.root.Open(e.path)
}

func (e fsEntry) Stat() (fs.FileInfo, error) {
	return e.info, e.infoErr
}
