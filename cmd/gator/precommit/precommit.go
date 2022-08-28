package precommit

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/gatekeeper/pkg/gator"
	"github.com/open-policy-agent/gatekeeper/pkg/gator/test"
	"github.com/open-policy-agent/gatekeeper/pkg/util"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

//go:embed bash/validate.sh
var validateScript string

const (
	examples = `  # Configures "gator vaidate" to run as a pre-commit hook in your project.
  # Gator will test changed resources against defined Constratints and ConstraintTemplates, 
  and fail the commit if any violations are detected.
  # See: https://github.com/tdesrosi/pre-validate

  # Sets up a pre-commit hook with the configuration you specify:
  > gator precommit --setup <gator test syntax>

  # For example, set up a pre-commit hook to test a directory:
  > gator precommit --setup --filename="constraints-and-templates/"

  # Set up a pre-commit hook to use multiple inputs:
  > gator precommit --setup --filename="templates/" --filename="constraints/"

  # Output structured violations data when precommit find errors:
  > gator precommit --setup --filename="constraints-and-templates/" --output=json

  # Removes the code from your precommit hook pertaining to this tool:
  > gator precommit --remove 

  For more information on using this tool, see 
  https://open-policy-agent.github.io/gatekeeper/website/docs/gator `
)

var Cmd = &cobra.Command{
	Use: "precommit",
	Short: `Configures "gator vaidate" to run as a pre-commit hook in your project. 
	Gator will test changed resources against a defined test suite before the commit is intiated, 
	and fail the commit if any violations are detected.`,
	Example: examples,
	Run:     run,
	Args:    cobra.NoArgs,
}

var allowedExtensions = []string{".yaml", ".yml", ".json"}

var (
	flagFilenames []string
	flagOutput    string
	flagSetup     bool
	flagRemove    bool
)

const (
	flagNameSetup    = "setup"
	flagNameRemove   = "remove"
	flagNameFilename = "filename"
	flagNameOutput   = "output"

	stringJSON = "json"
	stringYAML = "yaml"
)

func init() {
	Cmd.Flags().BoolVarP(&flagSetup, flagNameSetup, "s", false, "Use to tell gator you wish to set up your precommit hook, or update and existing configuration")
	Cmd.Flags().BoolVarP(&flagRemove, flagNameRemove, "s", false, "Use to tell gator you wish to set up your precommit hook, or update and existing configuration")
	Cmd.Flags().StringArrayVarP(&flagFilenames, flagNameFilename, "f", []string{}, "A file or directory containing Constraints and/or ConstraintTemplates.  Can be specified multiple times.")
	Cmd.Flags().StringVarP(&flagOutput, flagNameOutput, "o", "", fmt.Sprintf("Output format.  One of: %s|%s.", stringJSON, stringYAML))
}

func run(cmd *cobra.Command, args []string) {
	unstrucs, err := readSources(flagFilenames)
	if err != nil {
		errFatalf("reading: %v", err)
	}
	if len(unstrucs) == 0 {
		errFatalf("no input data identified")
	}

	responses, err := test.Test(unstrucs)
	if err != nil {
		errFatalf("auditing objects: %v\n", err)
	}
	results := responses.Results()

	switch flagOutput {
	case stringJSON:
		b, err := json.MarshalIndent(results, "", "    ")
		if err != nil {
			errFatalf("marshaling validation json results: %v", err)
		}
		fmt.Print(string(b))
	case stringYAML:
		jsonb, err := json.Marshal(results)
		if err != nil {
			errFatalf("pre-marshaling results to json: %v", err)
		}

		unmarshalled := []*types.Result{}
		err = json.Unmarshal(jsonb, &unmarshalled)
		if err != nil {
			errFatalf("pre-unmarshaling results from json: %v", err)
		}

		yamlb, err := yaml.Marshal(unmarshalled)
		if err != nil {
			errFatalf("marshaling validation yaml results: %v", err)
		}
		fmt.Print(string(yamlb))
	default:
		if len(results) > 0 {
			for _, result := range results {
				fmt.Printf("Message: %q", result.Msg)
			}
		}
	}

	// Whether or not we return non-zero depends on whether we have a `deny`
	// enforcementAction on one of the violated constraints
	exitCode := 0
	if enforceableFailure(results) {
		exitCode = 1
	}
	os.Exit(exitCode)
}

func enforceableFailure(results []*types.Result) bool {
	for _, result := range results {
		if result.EnforcementAction == string(util.Deny) {
			return true
		}
	}

	return false
}

func readSources(filenames []string) ([]*unstructured.Unstructured, error) {
	var unstrucs []*unstructured.Unstructured

	// read from flags if available
	us, err := ReadFiles(filenames)
	if err != nil {
		return nil, fmt.Errorf("reading from filenames: %w", err)
	}
	unstrucs = append(unstrucs, us...)

	// check if stdin has data.  Read if so.
	us, err = readStdin()
	if err != nil {
		return nil, fmt.Errorf("reading from stdin: %w", err)
	}
	unstrucs = append(unstrucs, us...)

	return unstrucs, nil
}

func ReadFiles(filenames []string) ([]*unstructured.Unstructured, error) {
	var unstrucs []*unstructured.Unstructured

	// verify that the filenames aren't themselves disallowed extensions.  This
	// yields a much better user experience when the user mis-uses the
	// --filename flag.
	for _, name := range filenames {
		// make sure it's a file, not a directory
		fileInfo, err := os.Stat(name)
		if err != nil {
			return nil, fmt.Errorf("stat on path %q: %w", name, err)
		}

		if fileInfo.IsDir() {
			continue
		}
		if !allowedExtension(name) {
			return nil, fmt.Errorf("path %q must be of extensions: %v", name, allowedExtensions)
		}
	}

	// normalize directories by listing their files
	normalized, err := normalize(filenames)
	if err != nil {
		return nil, fmt.Errorf("normalizing filenames: %w", err)
	}

	for _, filename := range normalized {
		file, err := os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("opening file %q: %w", filename, err)
		}
		defer file.Close()

		us, err := gator.ReadK8sResources(bufio.NewReader(file))
		if err != nil {
			return nil, fmt.Errorf("reading file %q: %w", filename, err)
		}

		unstrucs = append(unstrucs, us...)
	}

	return unstrucs, nil
}

func readStdin() ([]*unstructured.Unstructured, error) {
	stdinfo, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("getting stdin info: %w", err)
	}

	if stdinfo.Size() == 0 {
		return nil, nil
	}

	us, err := gator.ReadK8sResources(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading: %w", err)
	}

	return us, nil
}

func normalize(filenames []string) ([]string, error) {
	var output []string

	for _, filename := range filenames {
		paths, err := filesBelow(filename)
		if err != nil {
			return nil, fmt.Errorf("filename %q: %w", filename, err)
		}
		output = append(output, paths...)
	}

	return output, nil
}

// filesBelow walks the filetree from startPath and below, collecting a list of
// all the filepaths.  Directories are excluded.
func filesBelow(startPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(startPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// only add files to the normalized output
		if info.IsDir() {
			return nil
		}

		// make sure the file extension is valid
		if !allowedExtension(path) {
			return nil
		}

		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking: %w", err)
	}

	return files, nil
}

func allowedExtension(path string) bool {
	for _, ext := range allowedExtensions {
		if ext == filepath.Ext(path) {
			return true
		}
	}

	return false
}

func errFatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}
