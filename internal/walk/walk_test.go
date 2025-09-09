package walk_test

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/walk"

	"github.com/anchore/stereoscope"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestFS(t *testing.T) {
	tempdir := t.TempDir()
	root, err := os.OpenRoot(tempdir)
	require.NoError(t, err)

	err = root.Mkdir("a", 0o755)
	require.NoError(t, err)
	aTXT, err := root.Create("a/a.txt")
	require.NoError(t, err)
	_, err = aTXT.Write([]byte("hello a.txt\n"))
	require.NoError(t, err)
	err = root.Mkdir("a/b", 0o755)
	require.NoError(t, err)
	err = root.Mkdir("a/X", 0o755)
	require.NoError(t, err)
	xTXT, err := root.Create("a/X/X.txt")
	require.NoError(t, err)
	_, err = xTXT.Write([]byte("X.txt is not accessible\n"))
	require.NoError(t, err)

	// simulate permission denied error on a/X
	err = os.Chmod(filepath.Join(tempdir, "a", "X"), 0x000)
	require.NoError(t, err)
	t.Cleanup(
		func() {
			err = os.Chmod(filepath.Join(tempdir, "a", "X"), 0o755)
			require.NoError(t, err)
		})

	actual := make([]then, 0, 10)
	for entry, err := range walk.FS(t.Context(), root) {
		actual = append(actual, testEntry(t, entry, err))
	}

	require.Len(t, actual, 2)
	require.ElementsMatch(t,
		[]then{
			{path: filepath.Join(tempdir, "a/a.txt"), size: 12},
			{path: filepath.Join(tempdir, "a/X"), size: 0, err: &fs.PathError{
				Op:   "openat",
				Path: "a/X",
				Err:  syscall.EACCES,
			}},
		},
		actual,
	)
}

func TestImage(t *testing.T) {
	tempdir := t.TempDir()
	root, err := os.OpenRoot(tempdir)
	require.NoError(t, err)

	err = root.Mkdir("a", 0o755)
	require.NoError(t, err)
	aTXT, err := root.Create("a/a.txt")
	require.NoError(t, err)
	_, err = aTXT.Write([]byte("hello a.txt\n"))
	require.NoError(t, err)
	err = root.Mkdir("a/b", 0o755)
	require.NoError(t, err)
	err = root.Mkdir("a/c", 0o755)
	require.NoError(t, err)
	xTXT, err := root.Create("a/c/c.txt")
	require.NoError(t, err)
	_, err = xTXT.Write([]byte("layer1\n"))
	require.NoError(t, err)

	// /a/c/c.txt has a different content in new layer
	// seeker deals with squashed layers, because that's what is
	// visible when container is running
	dockerfile := []byte(`
FROM busybox:latest
COPY a/ /a/
# overwrite c/c.txt in a new layer
RUN echo "this is a new layer, longer content is 42" > /a/c/c.txt
`)
	f, err := root.Create("Dockerfile")
	require.NoError(t, err)
	t.Cleanup(func() {
		err = f.Close()
		require.NoError(t, err)
	})
	_, err = f.Write([]byte(dockerfile))
	require.NoError(t, err)
	err = f.Sync()
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    tempdir,
			Dockerfile: "Dockerfile",
		},
		WaitingFor: wait.ForExit(),
	}

	c, err := testcontainers.GenericContainer(t.Context(), testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	info, err := c.Inspect(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		err = c.Terminate(context.Background())
		require.NoError(t, err)
	})

	ociImage, err := stereoscope.GetImageFromSource(
		t.Context(),
		info.Image,
		image.DockerDaemonSource,
		nil,
	)
	require.NoError(t, err)

	actual := make([]then, 0, 10)
	for entry, err := range walk.Image(t.Context(), ociImage) {
		if strings.HasPrefix(entry.Path(), "/a") {
			actual = append(actual, testEntry(t, entry, err))
		}
	}

	require.Len(t, actual, 2)
	require.ElementsMatch(t,
		[]then{
			{path: "/a/a.txt", size: 12},
			{path: "/a/c/c.txt", size: 42}, // len of RUN echo command above
		},
		actual,
	)

}

type then struct {
	path string
	size int64
	err  error
}

func testEntry(t *testing.T, entry walk.Entry, err error) then {
	t.Helper()
	if err != nil {
		return then{
			path: entry.Path(),
			err:  err,
		}
	}

	f, openErr := entry.Open()
	require.NoError(t, openErr)
	var b []byte
	t.Cleanup(func() {
		require.NoError(t, f.Close())
	})
	b, err = io.ReadAll(f)
	require.NoError(t, err)

	info, err := entry.Stat()
	require.NoError(t, err)
	require.Equal(t, int64(len(b)), info.Size())

	return then{path: entry.Path(), size: int64(len(b))}
}
