// Copyright 2021 The Audit Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package capabilities

import (
	"archive/tar"
	"capabilities-tool/pkg"
	"capabilities-tool/pkg/models"
	index "capabilities-tool/pkg/reports/capabilities"
	"fmt"
	"github.com/gobuffalo/envy"
	"github.com/google/go-containerregistry/pkg/crane"
	_ "github.com/mattn/go-sqlite3"
	operatorv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var flags = index.BindFlags{}

var prioritizedInstallModes = []string{
	string(operatorv1alpha1.InstallModeTypeOwnNamespace),
	string(operatorv1alpha1.InstallModeTypeSingleNamespace),
	string(operatorv1alpha1.InstallModeTypeMultiNamespace),
	string(operatorv1alpha1.InstallModeTypeAllNamespaces),
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "capabilities",
		Short:   "A utility that allows you to pre-test your operator bundles before submitting for Red Hat Certification.",
		Long:    "",
		PreRunE: validation,
		RunE:    run,
	}

	currentPath, err := os.Getwd()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	cmd.Flags().StringVar(&flags.PackageName, "package-name", "",
		"filter by the Package names which are like *package-name*. Required for Operator Clean-up")
	cmd.Flags().BoolVar(&flags.InstallMode, "install-mode", false,
		"filter by the Package names which are like *package-name*. Required for Operator Clean-up")
	cmd.Flags().StringVar(&flags.BundleName, "bundle-name", "",
		"filter by the Bundle names which are like *bundle-name*")
	cmd.Flags().StringVar(&flags.FilterBundle, "bundle-image", "",
		"filter by the Bundle names which are like *bundle-image*")
	cmd.Flags().StringVar(&flags.OutputFormat, "output", pkg.JSON,
		fmt.Sprintf("inform the output format. [Options: %s]", pkg.JSON))
	cmd.Flags().StringVar(&flags.OutputPath, "output-path", currentPath,
		"inform the path of the directory to output the report. (Default: current directory)")
	cmd.Flags().StringVar(&flags.S3Bucket, "bucket-name", "",
		"minio bucket name where result will be stored")
	cmd.Flags().StringVar(&flags.Endpoint, "endpoint", envy.Get("MINIO_ENDPOINT", ""), ""+
		"minio endpoint where bucket will be created")
	cmd.Flags().StringVar(&flags.ContainerEngine, "container-engine", pkg.Docker,
		fmt.Sprintf("specifies the container tool to use. If not set, the default value is docker. "+
			"Note that you can use the environment variable CONTAINER_ENGINE to inform this option. "+
			"[Options: %s and %s]", pkg.Docker, pkg.Podman))
	cmd.Flags().StringVar(&flags.PullSecretName, "pull-secret-name", "registry-pull-secret",
		"Name of Kubernetes Secret to use for pulling registry images")
	cmd.Flags().StringVar(&flags.ServiceAccount, "service-account", "default",
		"Name of Kubernetes Service Account to use")

	return cmd
}

func validation(cmd *cobra.Command, args []string) error {

	if len(flags.OutputFormat) > 0 && flags.OutputFormat != pkg.JSON {
		return fmt.Errorf("invalid value informed via the --output flag :%v. "+
			"The available option is: %s", flags.OutputFormat, pkg.JSON)
	}

	if len(flags.OutputPath) > 0 {
		if _, err := os.Stat(flags.OutputPath); os.IsNotExist(err) {
			return err
		}
	}

	if len(flags.ContainerEngine) == 0 {
		flags.ContainerEngine = pkg.GetContainerToolFromEnvVar()
	}

	if flags.ContainerEngine != pkg.Docker && flags.ContainerEngine != pkg.Podman {
		return fmt.Errorf("invalid value for the flag --container-engine (%s)."+
			" The valid options are %s and %s", flags.ContainerEngine, pkg.Docker, pkg.Podman)
	}

	return nil
}

func run(cmd *cobra.Command, args []string) error {
	log.Info("Running capabilities run function")

	reportData := index.Data{}
	reportData.Flags = flags
	pkg.GenerateTemporaryDirs()

	var Bundle models.AuditCapabilities
	targetNamespaces := []string{"default"}

	if flags.InstallMode {
		targetNamespaces, _ = RunInstallMode(flags.FilterBundle)
	}

	log.Info("Deploying operator with operator-sdk...")
	operatorsdk := exec.Command("operator-sdk", "run", "bundle", flags.FilterBundle, "--pull-secret-name", flags.PullSecretName, "--timeout", "5m", "--namespace", targetNamespaces[0])
	runCommand, err := pkg.RunCommand(operatorsdk)

	if err != nil {
		log.Errorf("Unable to run operator-sdk run bundle: %v\n", err)
	}

	RBLogs := string(runCommand[:])
	Bundle.InstallLogs = append(Bundle.InstallLogs, RBLogs)
	Bundle.OperatorBundleImagePath = flags.FilterBundle
	Bundle.OperatorBundleName = flags.BundleName

	reportData.AuditCapabilities = append(reportData.AuditCapabilities, Bundle)
	reportData.AuditCapabilities[0].Capabilities = false

	if strings.Contains(RBLogs, "OLM has successfully installed") {
		log.Info("Operator Installed Successfully")
		reportData.AuditCapabilities[0].Capabilities = true
	}

	if flags.PackageName != "" {
		log.Info("Cleaning up installed Operator:", flags.PackageName)
		Bundle.PackageName = flags.PackageName
		cleanup := exec.Command("operator-sdk", "cleanup", flags.PackageName)
		runCleanup, err := pkg.RunCommand(cleanup)
		if err != nil {
			log.Errorf("Unable to run operator-sdk cleanup: %v\n", err)
		}
		CLogs := string(runCleanup)
		reportData.AuditCapabilities[0].CleanUpLogs = append(reportData.AuditCapabilities[0].CleanUpLogs, CLogs)
	}

	log.Info("Generating output...")
	if err := reportData.OutputReport(); err != nil {
		return err
	}

	if flags.S3Bucket != "" {
		log.Info("Uploading result to S3")
		filename := pkg.GetReportName(reportData.Flags.BundleName, "cap_level_1", "json")
		path := filepath.Join(reportData.Flags.OutputPath, filename)
		if err := pkg.WriteDataToS3(path, filename, flags.S3Bucket, flags.Endpoint); err != nil {
			return err
		}
	}

	log.Info("Task Completed!!!!!")

	return nil
}

func untar(dst string, r io.Reader) error {
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()

		switch {

		// if no more files are found return
		case err == io.EOF:
			return nil

		// return any other error
		case err != nil:
			return err

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		target := filepath.Join(dst, header.Name)

		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()

		// check the file type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0o755); err != nil {
					return err
				}
			}

		// if it's a file create it
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()

			// if it's a link create it
		case tar.TypeSymlink:
			err := os.Symlink(header.Linkname, filepath.Join(dst, header.Name))
			if err != nil {
				log.Println(fmt.Sprintf("Error creating link: %s. Ignoring.", header.Name))
				continue
			}
		}
	}
}

func getCsvFilePathFromBundle(mountedDir string) (string, error) {
	log.Trace("reading clusterserviceversion file from the bundle")
	log.Debug("mounted directory is ", mountedDir)
	matches, err := filepath.Glob(filepath.Join(mountedDir, "manifests", "*.clusterserviceversion.yaml"))
	if err != nil {
		log.Error("glob pattern is malformed: ", err)
		return "", err
	}
	if len(matches) == 0 {
		log.Error("unable to find clusterserviceversion file in the bundle image: ", err)
		return "", err
	}
	if len(matches) > 1 {
		log.Error("found more than one clusterserviceversion file in the bundle image: ", err)
		return "", err
	}
	log.Debugf("The path to csv file is %s", matches[0])
	return matches[0], nil
}

func RunInstallMode(PackageName string) ([]string, error) {
	log.Info("Pulling image: ", flags.FilterBundle)

	options := make([]crane.Option, 0)
	img, err := crane.Pull(flags.FilterBundle, options...)
	if err != nil {
		return nil, fmt.Errorf("Unable to pull image: %v\n", err)
	}

	containerFSPath := path.Join("tmp", "bundle")
	if err := os.Mkdir(containerFSPath, 0o755); err != nil {
		return nil, fmt.Errorf("%s: %s", containerFSPath, err)
	}

	// export/flatten, and extract
	log.Debug("exporting and flattening image")
	r, w := io.Pipe()
	go func() {
		defer w.Close()
		log.Debugf("writing container filesystem to output dir: %s", containerFSPath)
		err = crane.Export(img, w)
		if err != nil {
			log.Error("unable to export and flatten container filesystem:", err)
		}
	}()

	log.Debug("extracting container filesystem to ", containerFSPath)
	if err := untar(containerFSPath, r); err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	installedModes, err := GetSupportedInstalledModes("tmp/bundle")
	log.Info(installedModes)

	var installMode string
	for i := 0; i < len(prioritizedInstallModes); i++ {
		if _, ok := installedModes[prioritizedInstallModes[i]]; ok {
			installMode = prioritizedInstallModes[i]
			break
		}
	}
	log.Info(installMode)
	log.Debugf("The operator install mode is %s", installMode)
	targetNamespaces := make([]string, 2)

	switch installMode {
	case string(operatorv1alpha1.InstallModeTypeOwnNamespace):
		targetNamespaces = []string{flags.PackageName}
	case string(operatorv1alpha1.InstallModeTypeSingleNamespace):
		targetNamespaces = []string{flags.PackageName + "-target"}
	case string(operatorv1alpha1.InstallModeTypeMultiNamespace):
		targetNamespaces = []string{flags.PackageName, flags.PackageName + "-target"}
	case string(operatorv1alpha1.InstallModeTypeAllNamespaces):
		targetNamespaces = []string{}

	}
	log.Info("Creating namespace: ", targetNamespaces)
	createNamespace := exec.Command("oc", "new-project", targetNamespaces[0])
	_, err = pkg.RunCommand(createNamespace)

	if err != nil {
		log.Errorf("Unable to create namespace: ", err)
	}

	return targetNamespaces, nil
}

func GetSupportedInstalledModes(mountedDir string) (map[string]bool, error) {
	csvFilepath, err := getCsvFilePathFromBundle(mountedDir)
	if err != nil {
		return nil, err
	}

	csvFileReader, err := os.ReadFile(csvFilepath)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	var csv ClusterServiceVersion
	err = yaml.Unmarshal(csvFileReader, &csv)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	var installedModes map[string]bool = make(map[string]bool, len(csv.Spec.InstallModes))
	for _, v := range csv.Spec.InstallModes {
		if v.Supported {
			installedModes[v.Type] = true
		}
	}
	return installedModes, nil
}

type ClusterServiceVersion struct {
	Spec ClusterServiceVersionSpec `yaml:"spec"`
}

type ClusterServiceVersionSpec struct {
	// InstallModes specify supported installation types
	InstallModes []InstallMode `yaml:"installModes,omitempty"`
}

type InstallMode struct {
	Type      string `yaml:"type"`
	Supported bool   `yaml:"supported"`
}
