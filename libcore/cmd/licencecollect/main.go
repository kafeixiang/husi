package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	_ "libcore" // Import dependencies

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"codeberg.org/xchacha20-poly1305/pkgsite-go"
)

const (
	DefaultTimeout             = 15 * time.Second
	DefaultRateLimitRetryDelay = 1 * time.Minute // In my own test, the pkg.go.dev's rate limit refreshes per minute.

	generatedLibraryFilePrefix = "go_"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	outputName := flag.String("o", "", "output")
	outputDir := flag.String("d", "", "output directory for AboutLibraries library definitions")
	cleanOutputDir := flag.Bool("clean", false, "remove generated library definitions from output directory before writing")
	flag.Parse()

	if *outputName != "" && *outputDir != "" {
		log.FatalContext(ctx, "only one of -o or -d can be set")
		return
	}

	var output io.Writer
	switch *outputName {
	case "", "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		file, err := os.Create(*outputName)
		if err != nil {
			log.FatalContext(ctx, "create output file", err)
			return
		}
		defer file.Close()
		output = file
	}

	buildInfo, loaded := debug.ReadBuildInfo()
	if !loaded {
		log.PanicContext(ctx, "failed to read build info")
		return
	}

	client := pkgsite.NewClient()
	libraries := make([]Library, 0, len(buildInfo.Deps))
	for _, dependency := range buildInfo.Deps {
		library, err := resolveLibrary(ctx, client, dependency)
		if err != nil {
			log.PanicContext(ctx, err)
			return
		}
		log.InfoContext(ctx, "found ", library.Name, " with license: ", fmt.Sprint(library.Licenses))
		libraries = append(libraries, library)
	}
	slices.SortFunc(libraries, func(a, b Library) int {
		return cmp.Compare(a.UniqueID, b.UniqueID)
	})

	if *outputDir != "" {
		err := writeToDir(*outputDir, libraries, *cleanOutputDir)
		if err != nil {
			log.PanicContext(ctx, "write libraries", err)
			return
		}
		return
	}

	err := json.NewEncoder(output).Encode(libraries)
	if err != nil {
		log.PanicContext(ctx, "encode json ", err)
		return
	}
}

func writeToDir(outputDir string, libraries []Library, clean bool) error {
	err := os.MkdirAll(outputDir, 0o755)
	if err != nil {
		return err
	}
	if clean {
		err = cleanGeneratedLibraries(outputDir)
		if err != nil {
			return err
		}
	}
	for _, library := range libraries {
		file, err := os.Create(libraryFileName(outputDir, library.UniqueID))
		if err != nil {
			return err
		}
		err = json.NewEncoder(file).Encode(library)
		_ = file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanGeneratedLibraries(outputDir string) error {
	matches, err := filepath.Glob(filepath.Join(outputDir, generatedLibraryFilePrefix+"*.json"))
	if err != nil {
		return E.Cause(err, "glob ", outputDir)
	}
	for _, match := range matches {
		err = os.Remove(match)
		if err != nil {
			return err
		}
	}
	return nil
}

var libraryNameReplacer = strings.NewReplacer("/", "_", "\\", "_", ":", "_")

func libraryFileName(outputDir string, uniqueID string) string {
	return filepath.Join(outputDir, generatedLibraryFilePrefix+libraryNameReplacer.Replace(uniqueID)+".json")
}

func resolveLibrary(ctx context.Context, client *pkgsite.Client, module *debug.Module) (Library, error) {
	// Currently, we don't need to resolve replaced module's real path.
	// Because replaced module usually not changed its path to another unique one.
	pkgModule, err := resolveModule(ctx, client, module.Path, &pkgsite.ModuleOptions{
		Version:  module.Version,
		Licenses: true,
	})
	// For the pseudo versions that unrecorded
	if err != nil && module.Version != "" && isNotFound(err) {
		pkgModule, err = resolveModule(ctx, client, module.Path, &pkgsite.ModuleOptions{
			Licenses: true,
		})
	}
	if err != nil {
		return Library{}, E.Cause(err, "resolve ", module.Path)
	}
	licenses := common.FlatMap(pkgModule.Licenses, func(it pkgsite.License) []string {
		return it.Types
	})
	// https://github.com/google/licensecheck can't parses sing library's license well.
	if strings.HasPrefix(path.Base(module.Path), "sing") {
		index := slices.Index(licenses, LicenseGPL2)
		if index < 0 {
			// github.com/dyhkwong/sing-juicity
			index = slices.Index(licenses, LicenseGPL3)
		}
		if index >= 0 {
			licenses[index] = LicenseGPL3OrLatter
		}
	}
	slices.Sort(licenses)
	licenses = slices.Clip(slices.Compact(licenses))
	return Library{
		UniqueID:        module.Path,
		ArtifactVersion: module.Version,
		Name:            module.Path,
		Website:         pkgModule.RepoURL,
		Licenses:        licenses,
	}, nil
}

func resolveModule(ctx context.Context, client *pkgsite.Client, modulePath string, options *pkgsite.ModuleOptions) (*pkgsite.Module, error) {
	for {
		pkgModule, err := requestModule(ctx, client, modulePath, options)
		if !isTooManyRequests(err) {
			return pkgModule, err
		}
		log.WarnContext(ctx, "pkgsite rate limited while resolving ", modulePath, ", retrying in ", DefaultRateLimitRetryDelay)
		select {
		case <-time.After(DefaultRateLimitRetryDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func requestModule(ctx context.Context, client *pkgsite.Client, modulePath string, options *pkgsite.ModuleOptions) (*pkgsite.Module, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	return client.Module(ctx, modulePath, options)
}

func isNotFound(err error) bool {
	return isHTTPErrorCode(err, http.StatusNotFound)
}

func isTooManyRequests(err error) bool {
	return isHTTPErrorCode(err, http.StatusTooManyRequests)
}

func isHTTPErrorCode(err error, code int) bool {
	apiError, isAPIError := errors.AsType[*pkgsite.APIError](err)
	if !isAPIError {
		return false
	}
	return apiError.Code == code
}
