// Copyright (c) 2016-2022 The Decred developers
// Use of this source code is governed by an ISC license that can be found in
// the LICENSE file.

package tbc

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// unzip unzips src to dst.
// unzip borrowed from https://golangcode.com/unzip-files-in-go/
func unzip(src string, dest string) ([]string, error) {
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {
		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+
			string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path",
				fpath)
		}
		// log.Logf("Extracting: %v", f.Name)

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath,
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration
		// of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

// gunzip untars filename to destination.
func gunzip(filename, destination string) error {
	a, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	ab := bytes.NewReader(a)
	gz, err := gzip.NewReader(ab)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // end of archive
			}
			return err
		}
		if hdr == nil {
			continue
		}
		// log.Printf("Extracting: %v", hdr.Name)
		target := filepath.Join(destination, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR,
				os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}

			// copy to file
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}

			if err := f.Close(); err != nil {
				return err
			}
		}
	}

	return nil
}

// extract extracts the provided archive to the provided destination. It
// autodetects if it is a zip or a tar archive.
func extract(filename, dst string) error {
	// log.Printf("Extracting: %v -> %v\n", filename, dst)
	var err error
	archive := filepath.Ext(filename)
	switch archive {
	case ".zip":
		_, err = unzip(filename, dst)
	case ".gz":
		err = gunzip(filename, dst)
	default:
		err = fmt.Errorf("Unknown archive type: %v", archive)
	}
	return err
}
