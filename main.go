package main

import (
	"context"
	"fmt"
	"github.com/containers/common/pkg/auth"
	commonFlag "github.com/containers/common/pkg/flag"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage/pkg/reexec"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"repomgr/version"
	"strings"
)

// gitCommit will be the hash that the binary was built from
// and will be populated by the Makefile
var gitCommit = ""

var defaultUserAgent = "skopeo/" + version.Version

// requireSubcommand returns an error if no sub command is provided
// This was copied from podman: `github.com/containers/podman/cmd/podman/validate/args.go
// Some small style changes to match skopeo were applied, but try to apply any
// bugfixes there first.
func requireSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		suggestions := cmd.SuggestionsFor(args[0])
		if len(suggestions) == 0 {
			return fmt.Errorf("Unrecognized command `%[1]s %[2]s`\nTry '%[1]s --help' for more information", cmd.CommandPath(), args[0])
		}
		return fmt.Errorf("Unrecognized command `%[1]s %[2]s`\n\nDid you mean this?\n\t%[3]s\n\nTry '%[1]s --help' for more information", cmd.CommandPath(), args[0], strings.Join(suggestions, "\n\t"))
	}
	return fmt.Errorf("Missing command '%[1]s COMMAND'\nTry '%[1]s --help' for more information", cmd.CommandPath())
}

// createApp returns a cobra.Command, and the underlying globalOptions object, to be run or tested.
func createApp() (*cobra.Command, *globalOptions) {
	opts := globalOptions{}

	rootCommand := &cobra.Command{
		Use:               "repomgr",
		Long:              "Various operations with container images and container image registries",
		RunE:              requireSubcommand,
		PersistentPreRunE: opts.before,
		SilenceUsage:      true,
		SilenceErrors:     true,
		// Hide the completion command which is provided by cobra
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
		// This is documented to parse "local" (non-PersistentFlags) flags of parent commands before
		// running subcommands and handling their options. We don't really run into such cases,
		// because all of our flags on rootCommand are in PersistentFlags, except for the deprecated --tls-verify;
		// in that case we need TraverseChildren so that we can distinguish between
		// (skopeo --tls-verify inspect) (causes a warning) and (skopeo inspect --tls-verify) (no warning).
		TraverseChildren: true,
	}
	if gitCommit != "" {
		rootCommand.Version = fmt.Sprintf("%s commit: %s", version.Version, gitCommit)
	} else {
		rootCommand.Version = version.Version
	}
	// Override default `--version` global flag to enable `-v` shorthand
	var dummyVersion bool
	rootCommand.Flags().BoolVarP(&dummyVersion, "version", "v", false, "Version for Skopeo")
	rootCommand.PersistentFlags().BoolVar(&opts.debug, "debug", false, "enable debug output")
	rootCommand.PersistentFlags().StringVar(&opts.policyPath, "policy", "", "Path to a trust policy file")
	rootCommand.PersistentFlags().BoolVar(&opts.insecurePolicy, "insecure-policy", false, "run the tool without any policy check")
	rootCommand.PersistentFlags().StringVar(&opts.registriesDirPath, "registries.d", "", "use registry configuration files in `DIR` (e.g. for container signature storage)")
	rootCommand.PersistentFlags().StringVar(&opts.overrideArch, "override-arch", "", "use `ARCH` instead of the architecture of the machine for choosing images")
	rootCommand.PersistentFlags().StringVar(&opts.overrideOS, "override-os", "", "use `OS` instead of the running OS for choosing images")
	rootCommand.PersistentFlags().StringVar(&opts.overrideVariant, "override-variant", "", "use `VARIANT` instead of the running architecture variant for choosing images")
	rootCommand.PersistentFlags().DurationVar(&opts.commandTimeout, "command-timeout", 0, "timeout for the command execution")
	rootCommand.PersistentFlags().StringVar(&opts.registriesConfPath, "registries-conf", "", "path to the registries.conf file")
	if err := rootCommand.PersistentFlags().MarkHidden("registries-conf"); err != nil {
		logrus.Fatal("unable to mark registries-conf flag as hidden")
	}
	rootCommand.PersistentFlags().StringVar(&opts.tmpDir, "tmpdir", "", "directory used to store temporary files")
	flag := commonFlag.OptionalBoolFlag(rootCommand.Flags(), &opts.tlsVerify, "tls-verify", "Require HTTPS and verify certificates when accessing the registry")
	flag.Hidden = true
	rootCommand.AddCommand(
		copyCmd(&opts),
		deleteCmd(&opts),
		generateSigstoreKeyCmd(),
		inspectCmd(&opts),
		layersCmd(&opts),
		loginCmd(&opts),
		logoutCmd(&opts),
		manifestDigestCmd(),
		proxyCmd(&opts),
		syncCmd(&opts),
		standaloneSignCmd(),
		standaloneVerifyCmd(),
		tagsCmd(&opts),
		untrustedSignatureDumpCmd(),
	)
	return rootCommand, &opts
}

// before is run by the cli package for any command, before running the command-specific handler.
func (opts *globalOptions) before(cmd *cobra.Command, args []string) error {
	if opts.debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if opts.tlsVerify.Present() {
		logrus.Warn("'--tls-verify' is deprecated, please set this on the specific subcommand")
	}
	return nil
}

func main() {
	if reexec.Init() {
		return
	}
	rootCmd, _ := createApp()
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

// getPolicyContext returns a *signature.PolicyContext based on opts.
func (opts *globalOptions) getPolicyContext() (*signature.PolicyContext, error) {
	var policy *signature.Policy // This could be cached across calls in opts.
	var err error
	if opts.insecurePolicy {
		policy = &signature.Policy{Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()}}
	} else if opts.policyPath == "" {
		policy, err = signature.DefaultPolicy(nil)
	} else {
		policy, err = signature.NewPolicyFromFile(opts.policyPath)
	}
	if err != nil {
		return nil, err
	}
	return signature.NewPolicyContext(policy)
}

// commandTimeoutContext returns a context.Context and a cancellation callback based on opts.
// The caller should usually "defer cancel()" immediately after calling this.
func (opts *globalOptions) commandTimeoutContext() (context.Context, context.CancelFunc) {
	ctx := context.Background()
	var cancel context.CancelFunc = func() {}
	if opts.commandTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.commandTimeout)
	}
	return ctx, cancel
}

// newSystemContext returns a *types.SystemContext corresponding to opts.
// It is guaranteed to return a fresh instance, so it is safe to make additional updates to it.
func (opts *globalOptions) newSystemContext() *types.SystemContext {
	ctx := &types.SystemContext{
		RegistriesDirPath:        opts.registriesDirPath,
		ArchitectureChoice:       opts.overrideArch,
		OSChoice:                 opts.overrideOS,
		VariantChoice:            opts.overrideVariant,
		SystemRegistriesConfPath: opts.registriesConfPath,
		BigFilesTemporaryDir:     opts.tmpDir,
		DockerRegistryUserAgent:  defaultUserAgent,
	}
	// DEPRECATED: We support this for backward compatibility, but override it if a per-image flag is provided.
	if opts.tlsVerify.Present() {
		ctx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.Value())
	}
	return ctx
}

func deleteCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := imageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()
	opts := deleteOptions{
		global:    global,
		image:     imageOpts,
		retryOpts: retryOpts,
	}
	cmd := &cobra.Command{
		Use:   "delete [command options] IMAGE-NAME",
		Short: "Delete image IMAGE-NAME",
		Long: fmt.Sprintf(`Delete an "IMAGE_NAME" from a transport
Supported transports:
%s
See skopeo(1) section "IMAGE NAMES" for the expected format
`, strings.Join(transports.ListNames(), ", ")),
		RunE:              commandAction(opts.run),
		Example:           `skopeo delete docker://registry.example.com/example/pause:latest`,
		ValidArgsFunction: autocompleteSupportedTransports,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	return cmd
}

func copyCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	deprecatedTLSVerifyFlags, deprecatedTLSVerifyOpt := deprecatedTLSVerifyFlags()
	srcFlags, srcOpts := imageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "src-", "screds")
	destFlags, destOpts := imageDestFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "dest-", "dcreds")
	retryFlags, retryOpts := retryFlags()
	opts := copyOptions{global: global,
		deprecatedTLSVerify: deprecatedTLSVerifyOpt,
		srcImage:            srcOpts,
		destImage:           destOpts,
		retryOpts:           retryOpts,
	}
	cmd := &cobra.Command{
		Use:   "copy [command options] SOURCE-IMAGE DESTINATION-IMAGE",
		Short: "Copy an IMAGE-NAME from one location to another",
		Long: fmt.Sprintf(`Container "IMAGE-NAME" uses a "transport":"details" format.

Supported transports:
%s

See skopeo(1) section "IMAGE NAMES" for the expected format
`, strings.Join(transports.ListNames(), ", ")),
		RunE:              commandAction(opts.run),
		Example:           `skopeo copy docker://quay.io/skopeo/stable:latest docker://registry.example.com/skopeo:latest`,
		ValidArgsFunction: autocompleteSupportedTransports,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&deprecatedTLSVerifyFlags)
	flags.AddFlagSet(&srcFlags)
	flags.AddFlagSet(&destFlags)
	flags.AddFlagSet(&retryFlags)
	flags.StringSliceVar(&opts.additionalTags, "additional-tag", []string{}, "additional tags (supports docker-archive)")
	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "Suppress output information when copying images")
	flags.BoolVarP(&opts.all, "all", "a", false, "Copy all images if SOURCE-IMAGE is a list")
	flags.Var(commonFlag.NewOptionalStringValue(&opts.multiArch), "multi-arch", `How to handle multi-architecture images (system, all, or index-only)`)
	flags.BoolVar(&opts.preserveDigests, "preserve-digests", false, "Preserve digests of images and lists")
	flags.BoolVar(&opts.removeSignatures, "remove-signatures", false, "Do not copy signatures from SOURCE-IMAGE")
	flags.StringVar(&opts.signByFingerprint, "sign-by", "", "Sign the image using a GPG key with the specified `FINGERPRINT`")
	flags.StringVar(&opts.signBySigstoreParamFile, "sign-by-sigstore", "", "Sign the image using a sigstore parameter file at `PATH`")
	flags.StringVar(&opts.signBySigstorePrivateKey, "sign-by-sigstore-private-key", "", "Sign the image using a sigstore private key at `PATH`")
	flags.StringVar(&opts.signPassphraseFile, "sign-passphrase-file", "", "Read a passphrase for signing an image from `PATH`")
	flags.StringVar(&opts.signIdentity, "sign-identity", "", "Identity of signed image, must be a fully specified docker reference. Defaults to the target docker reference.")
	flags.StringVar(&opts.digestFile, "digestfile", "", "Write the digest of the pushed image to the specified file")
	flags.VarP(commonFlag.NewOptionalStringValue(&opts.format), "format", "f", `MANIFEST TYPE (oci, v2s1, or v2s2) to use in the destination (default is manifest type of source, with fallbacks)`)
	flags.StringSliceVar(&opts.encryptionKeys, "encryption-key", []string{}, "*Experimental* key with the encryption protocol to use needed to encrypt the image (e.g. jwe:/path/to/key.pem)")
	flags.IntSliceVar(&opts.encryptLayer, "encrypt-layer", []int{}, "*Experimental* the 0-indexed layer indices, with support for negative indexing (e.g. 0 is the first layer, -1 is the last layer)")
	flags.StringSliceVar(&opts.decryptionKeys, "decryption-key", []string{}, "*Experimental* key needed to decrypt the image")
	return cmd
}

func generateSigstoreKeyCmd() *cobra.Command {
	var opts generateSigstoreKeyOptions
	cmd := &cobra.Command{
		Use:     "generate-sigstore-key [command options] --output-prefix PREFIX",
		Short:   "Generate a sigstore public/private key pair",
		RunE:    commandAction(opts.run),
		Example: "skopeo generate-sigstore-key --output-prefix my-key",
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.StringVar(&opts.outputPrefix, "output-prefix", "", "Write the keys to `PREFIX`.pub and `PREFIX`.private")
	flags.StringVar(&opts.passphraseFile, "passphrase-file", "", "Read a passphrase for the private key from `PATH`")
	return cmd
}

func inspectCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := imageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()
	opts := inspectOptions{
		global:    global,
		image:     imageOpts,
		retryOpts: retryOpts,
	}
	cmd := &cobra.Command{
		Use:   "inspect [command options] IMAGE-NAME",
		Short: "Inspect image IMAGE-NAME",
		Long: fmt.Sprintf(`Return low-level information about "IMAGE-NAME" in a registry/transport
Supported transports:
%s

See skopeo(1) section "IMAGE NAMES" for the expected format
`, strings.Join(transports.ListNames(), ", ")),
		RunE: commandAction(opts.run),
		Example: `skopeo inspect docker://registry.fedoraproject.org/fedora
skopeo inspect --config docker://docker.io/alpine
skopeo inspect --format "Name: {{.Name}} Digest: {{.Digest}}" docker://registry.access.redhat.com/ubi8`,
		ValidArgsFunction: autocompleteSupportedTransports,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.BoolVar(&opts.raw, "raw", false, "output raw manifest or configuration")
	flags.BoolVar(&opts.config, "config", false, "output configuration")
	flags.StringVarP(&opts.format, "format", "f", "", "Format the output to a Go template")
	flags.BoolVarP(&opts.doNotListTags, "no-tags", "n", false, "Do not list the available tags from the repository in the output")
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	return cmd
}

func layersCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := imageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()
	opts := layersOptions{
		global:    global,
		image:     imageOpts,
		retryOpts: retryOpts,
	}
	cmd := &cobra.Command{
		Hidden: true,
		Use:    "layers [command options] IMAGE-NAME [LAYER...]",
		Short:  "Get layers of IMAGE-NAME",
		RunE:   commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	return cmd
}

func loginCmd(global *globalOptions) *cobra.Command {
	opts := loginOptions{
		global: global,
	}
	cmd := &cobra.Command{
		Use:     "login [command options] REGISTRY",
		Short:   "Login to a container registry",
		Long:    "Login to a container registry on a specified server.",
		RunE:    commandAction(opts.run),
		Example: `skopeo login quay.io`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	commonFlag.OptionalBoolFlag(flags, &opts.tlsVerify, "tls-verify", "require HTTPS and verify certificates when accessing the registry")
	flags.AddFlagSet(auth.GetLoginFlags(&opts.loginOpts))
	return cmd
}

func logoutCmd(global *globalOptions) *cobra.Command {
	opts := logoutOptions{
		global: global,
	}
	cmd := &cobra.Command{
		Use:     "logout [command options] REGISTRY",
		Short:   "Logout of a container registry",
		Long:    "Logout of a container registry on a specified server.",
		RunE:    commandAction(opts.run),
		Example: `skopeo logout quay.io`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	commonFlag.OptionalBoolFlag(flags, &opts.tlsVerify, "tls-verify", "require HTTPS and verify certificates when accessing the registry")
	flags.AddFlagSet(auth.GetLogoutFlags(&opts.logoutOpts))
	return cmd
}

func manifestDigestCmd() *cobra.Command {
	var opts manifestDigestOptions
	cmd := &cobra.Command{
		Use:     "manifest-digest MANIFEST-FILE",
		Short:   "Compute a manifest digest of a file",
		RunE:    commandAction(opts.run),
		Example: "skopeo manifest-digest manifest.json",
	}
	adjustUsage(cmd)
	return cmd
}

func standaloneSignCmd() *cobra.Command {
	opts := standaloneSignOptions{}
	cmd := &cobra.Command{
		Use:   "standalone-sign [command options] MANIFEST DOCKER-REFERENCE KEY-FINGERPRINT --output|-o SIGNATURE",
		Short: "Create a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.StringVarP(&opts.output, "output", "o", "", "output the signature to `SIGNATURE`")
	flags.StringVarP(&opts.passphraseFile, "passphrase-file", "", "", "file that contains a passphrase for the --sign-by key")
	return cmd
}

func standaloneVerifyCmd() *cobra.Command {
	opts := standaloneVerifyOptions{}
	cmd := &cobra.Command{
		Use:   "standalone-verify MANIFEST DOCKER-REFERENCE KEY-FINGERPRINTS SIGNATURE",
		Short: "Verify a signature using local files",
		Long: `Verify a signature using local files

KEY-FINGERPRINTS can be a comma separated list of fingerprints, or "any" if you trust all the keys in the public key file.`,
		RunE: commandAction(opts.run),
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.publicKeyFile, "public-key-file", "", `File containing public keys. If not specified, will use local GPG keys.`)
	adjustUsage(cmd)
	return cmd
}

func untrustedSignatureDumpCmd() *cobra.Command {
	opts := untrustedSignatureDumpOptions{}
	cmd := &cobra.Command{
		Use:    "untrusted-signature-dump-without-verification SIGNATURE",
		Short:  "Dump contents of a signature WITHOUT VERIFYING IT",
		RunE:   commandAction(opts.run),
		Hidden: true,
	}
	adjustUsage(cmd)
	return cmd
}

func syncCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	deprecatedTLSVerifyFlags, deprecatedTLSVerifyOpt := deprecatedTLSVerifyFlags()
	srcFlags, srcOpts := dockerImageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "src-", "screds")
	destFlags, destOpts := dockerImageFlags(global, sharedOpts, deprecatedTLSVerifyOpt, "dest-", "dcreds")
	retryFlags, retryOpts := retryFlags()

	opts := syncOptions{
		global:              global,
		deprecatedTLSVerify: deprecatedTLSVerifyOpt,
		srcImage:            srcOpts,
		destImage:           &imageDestOptions{imageOptions: destOpts},
		retryOpts:           retryOpts,
	}

	cmd := &cobra.Command{
		Use:   "sync [command options] --src TRANSPORT --dest TRANSPORT SOURCE DESTINATION",
		Short: "Synchronize one or more images from one location to another",
		Long: `Copy all the images from a SOURCE to a DESTINATION.

Allowed SOURCE transports (specified with --src): docker, dir, yaml.
Allowed DESTINATION transports (specified with --dest): docker, dir.

See skopeo-sync(1) for details.
`,
		RunE:    commandAction(opts.run),
		Example: `skopeo sync --src docker --dest dir --scoped registry.example.com/busybox /media/usb`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.BoolVar(&opts.removeSignatures, "remove-signatures", false, "Do not copy signatures from SOURCE images")
	flags.StringVar(&opts.signByFingerprint, "sign-by", "", "Sign the image using a GPG key with the specified `FINGERPRINT`")
	flags.StringVar(&opts.signBySigstoreParamFile, "sign-by-sigstore", "", "Sign the image using a sigstore parameter file at `PATH`")
	flags.StringVar(&opts.signBySigstorePrivateKey, "sign-by-sigstore-private-key", "", "Sign the image using a sigstore private key at `PATH`")
	flags.StringVar(&opts.signPassphraseFile, "sign-passphrase-file", "", "File that contains a passphrase for the --sign-by key")
	flags.VarP(commonFlag.NewOptionalStringValue(&opts.format), "format", "f", `MANIFEST TYPE (oci, v2s1, or v2s2) to use when syncing image(s) to a destination (default is manifest type of source, with fallbacks)`)
	flags.StringVarP(&opts.source, "src", "s", "", "SOURCE transport type")
	flags.StringVarP(&opts.destination, "dest", "d", "", "DESTINATION transport type")
	flags.BoolVar(&opts.scoped, "scoped", false, "Images at DESTINATION are prefix using the full source image path as scope")
	flags.StringVar(&opts.appendSuffix, "append-suffix", "", "String to append to DESTINATION tags")
	flags.BoolVarP(&opts.all, "all", "a", false, "Copy all images if SOURCE-IMAGE is a list")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "Run without actually copying data")
	flags.BoolVar(&opts.preserveDigests, "preserve-digests", false, "Preserve digests of images and lists")
	flags.BoolVarP(&opts.keepGoing, "keep-going", "", false, "Do not abort the sync if any image copy fails")
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&deprecatedTLSVerifyFlags)
	flags.AddFlagSet(&srcFlags)
	flags.AddFlagSet(&destFlags)
	flags.AddFlagSet(&retryFlags)
	return cmd
}

func tagsCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := dockerImageFlags(global, sharedOpts, nil, "", "")
	retryFlags, retryOpts := retryFlags()

	opts := tagsOptions{
		global:    global,
		image:     imageOpts,
		retryOpts: retryOpts,
	}

	cmd := &cobra.Command{
		Use:   "list-tags [command options] SOURCE-IMAGE",
		Short: "List tags in the transport/repository specified by the SOURCE-IMAGE",
		Long: `Return the list of tags from the transport/repository "SOURCE-IMAGE"

Supported transports:
` + supportedTransports(" ") + `

See skopeo-list-tags(1) section "REPOSITORY NAMES" for the expected format
`,
		RunE:    commandAction(opts.run),
		Example: `skopeo list-tags docker://docker.io/fedora`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&retryFlags)
	return cmd
}

func proxyCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := imageFlags(global, sharedOpts, nil, "", "")
	opts := proxyOptions{global: global, imageOpts: imageOpts}
	cmd := &cobra.Command{
		Use:   "experimental-image-proxy [command options] IMAGE",
		Short: "Interactive proxy for fetching container images (EXPERIMENTAL)",
		Long:  `Run skopeo as a proxy, supporting HTTP requests to fetch manifests and blobs.`,
		RunE:  commandAction(opts.run),
		Args:  cobra.ExactArgs(0),
		// Not stabilized yet
		Hidden:  true,
		Example: `skopeo experimental-image-proxy --sockfd 3`,
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.IntVar(&opts.sockFd, "sockfd", 0, "Serve on opened socket pair (default 0/stdin)")
	return cmd
}

// autocompleteSupportedTransports list all supported transports with the colon suffix.
func autocompleteSupportedTransports(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	tps := transports.ListNames()
	suggestions := make([]string, 0, len(tps))
	for _, tp := range tps {
		suggestions = append(suggestions, tp+":")
	}
	return suggestions, cobra.ShellCompDirectiveNoFileComp
}
