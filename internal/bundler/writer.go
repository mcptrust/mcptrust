package bundler

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BundleOptions struct
type BundleOptions struct {
	LockfilePath  string
	SignaturePath string
	PublicKeyPath string
	PolicyPath    string
	OutputPath    string
}

// CreateBundle zip
func CreateBundle(opts BundleOptions, readmeContent string, manifest *BundleManifest) error {
	// output file
	outputFile, err := os.Create(opts.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// zip writer
	zipWriter := zip.NewWriter(outputFile)
	defer zipWriter.Close()

	// Add manifest.json first (alphabetically first: 'm' < 'p' < 'R')
	if manifest != nil {
		manifestJSON, err := manifest.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize manifest: %w", err)
		}
		if err := addStringToZip(zipWriter, string(manifestJSON), "manifest.json"); err != nil {
			return fmt.Errorf("failed to add manifest: %w", err)
		}
	}

	// Add files in stable alphabetical order
	// Order: manifest.json, mcp-lock.json, mcp-lock.json.sig, policy.yaml, public.key, README.txt

	// mcp-lock.json
	if err := addFileToZip(zipWriter, opts.LockfilePath, "mcp-lock.json"); err != nil {
		return fmt.Errorf("failed to add lockfile: %w", err)
	}

	// mcp-lock.json.sig
	if err := addFileToZip(zipWriter, opts.SignaturePath, "mcp-lock.json.sig"); err != nil {
		return fmt.Errorf("failed to add signature: %w", err)
	}

	// policy.yaml (optional)
	if opts.PolicyPath != "" {
		if _, err := os.Stat(opts.PolicyPath); err == nil {
			if err := addFileToZip(zipWriter, opts.PolicyPath, "policy.yaml"); err != nil {
				return fmt.Errorf("failed to add policy: %w", err)
			}
		}
	}

	// public.key (optional)
	if opts.PublicKeyPath != "" {
		if _, err := os.Stat(opts.PublicKeyPath); err == nil {
			if err := addFileToZip(zipWriter, opts.PublicKeyPath, "public.key"); err != nil {
				return fmt.Errorf("failed to add public key: %w", err)
			}
		}
	}

	// README.txt
	if err := addStringToZip(zipWriter, readmeContent, "README.txt"); err != nil {
		return fmt.Errorf("failed to add README: %w", err)
	}

	return nil
}

// addFileToZip helper
func addFileToZip(zw *zip.Writer, srcPath, destName string) error {
	file, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	// use dest name
	header.Name = filepath.Base(destName)
	header.Method = zip.Deflate
	// deterministic time (ZIP epoch)
	header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

// addStringToZip helper
func addStringToZip(zw *zip.Writer, content, filename string) error {
	header := &zip.FileHeader{
		Name:     filename,
		Method:   zip.Deflate,
		Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = writer.Write([]byte(content))
	return err
}
