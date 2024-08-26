package v1

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/thanos-io/thanos/pkg/block"
	"github.com/thanos-io/thanos/pkg/block/metadata"
	"github.com/thanos-io/thanos/pkg/compactv2"
)

func NewRelabelConfig(label_name string, label_value string) *relabel.Config {
	return &relabel.Config{
		TargetLabel: label_name,
		Replacement: label_value,
		Regex:       relabel.MustNewRegexp(""),
		Action:      relabel.Replace,
	}
}

func ReLabelTSDB(logger log.Logger, block_id string, oldBlock string, newBlockDir string, relabelConfig []*relabel.Config) error {
	chunkPool := chunkenc.NewPool()
	changeLog := compactv2.NewChangeLog(io.Discard)

	var modifiers []compactv2.Modifier

	if len(relabelConfig) > 0 {
		modifiers = append(modifiers, compactv2.WithRelabelModifier(relabelConfig...))
	}

	meta, err := metadata.ReadFromDir(oldBlock)
	if err != nil {
		return fmt.Errorf("error reading metadata: %v", err)
	}

	b, err := tsdb.OpenBlock(logger, oldBlock, chunkPool)
	if err != nil {
		level.Error(logger).Log("unable to open tsdb block: %s", err.Error())
		return fmt.Errorf("unable to open tsdb block")
	}

	if err := os.MkdirAll(filepath.Join(newBlockDir, block_id), os.ModePerm); err != nil {
		return err
	}

	ctx := context.Background()
	d, err := block.NewDiskWriter(ctx, logger, filepath.Join(newBlockDir, block_id))
	if err != nil {
		return err
	}
	comp := compactv2.New(newBlockDir, logger, changeLog, chunkPool)
	p := compactv2.NewProgressLogger(logger, int(b.Meta().Stats.NumSeries))

	if err := comp.WriteSeries(ctx, []block.Reader{b}, d, p, modifiers...); err != nil {
		return fmt.Errorf("Error writing series: %v", err)
	}
	meta.Stats, err = d.Flush()
	if err != nil {
		return fmt.Errorf("Error unable to flush data: %v", err)
	}
	if err := meta.WriteToDir(logger, filepath.Join(newBlockDir, block_id)); err != nil {
		return err
	}
	return nil
}

func ExtractTarGz(gzipStream io.Reader, tsdbDir string) error {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return fmt.Errorf("ExtractTarGz: NewReader failed")
	}

	tarReader := tar.NewReader(uncompressedStream)

	for true {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("ExtractTarGz: Next() failed: %s", err.Error())
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(fmt.Sprintf("%v/%v", tsdbDir, header.Name), 0755); err != nil {
				return fmt.Errorf("ExtractTarGz: Mkdir() failed: %s", err.Error())
			}
		case tar.TypeReg:
			outFile, err := os.Create(fmt.Sprintf("%v/%v", tsdbDir, header.Name))
			if err != nil {
				return fmt.Errorf("ExtractTarGz: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return fmt.Errorf("ExtractTarGz: Copy() failed: %s", err.Error())
			}
			outFile.Close()

		default:
			return fmt.Errorf(
				"ExtractTarGz: uknown type: %s in %s",
				string(header.Typeflag),
				header.Name)
		}

	}
	return nil
}

func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}
