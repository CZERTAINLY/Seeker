package walk

import (
	"context"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
)

// Roots is a convenience wrapper around FS for os.Root. See FS for details.
func Roots(ctx context.Context, roots ...*os.Root) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for _, root := range roots {
			for entry, err := range FS(ctx, root.FS(), root.Name()) {
				if !yield(entry, err) {
					return
				}
			}
		}
	}
}

// FS recursively walks the filesystem rooted at root and return a handle for every regular file found.
// Or an error if file information retrieval fails.
// Each Entry's Path() is prefixed with name of a filesystem. In most cases it'll be an absolute
// path to the file. It does not follow symlinks.
func FS(ctx context.Context, root fs.FS, name string) iter.Seq2[Entry, error] {
	if root == nil {
		panic("root is nil")
	}

	return func(yield func(Entry, error) bool) {
		fn := func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			var entry = fsEntry{
				root:    root,
				abspath: filepath.Join(name, path),
				path:    path,
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
		}
		_ = fs.WalkDir(root, ".", fn)
	}
}

// fsEntry implements Entry for a filesystem
// it uses root.Open to open the file
type fsEntry struct {
	root    fs.FS
	abspath string
	path    string
	info    fs.FileInfo
	infoErr error
}

// returns the absolute path to the file
func (e fsEntry) Path() string {
	return e.abspath
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
