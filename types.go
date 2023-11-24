package main

import (
	"github.com/containers/common/pkg/auth"
	commonFlag "github.com/containers/common/pkg/flag"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	"sync"
	"time"
)

type globalOptions struct {
	debug              bool                    // Enable debug output
	tlsVerify          commonFlag.OptionalBool // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	policyPath         string                  // Path to a signature verification policy file
	insecurePolicy     bool                    // Use an "allow everything" signature verification policy
	registriesDirPath  string                  // Path to a "registries.d" registry configuration directory
	overrideArch       string                  // Architecture to use for choosing images, instead of the runtime one
	overrideOS         string                  // OS to use for choosing images, instead of the runtime one
	overrideVariant    string                  // Architecture variant to use for choosing images, instead of the runtime one
	commandTimeout     time.Duration           // Timeout for the command execution
	registriesConfPath string                  // Path to the "registries.conf" file
	tmpDir             string                  // Path to use for big temporary files
}

type copyOptions struct {
	global                   *globalOptions
	deprecatedTLSVerify      *deprecatedTLSVerifyOption
	srcImage                 *imageOptions
	destImage                *imageDestOptions
	retryOpts                *retry.Options
	additionalTags           []string                  // For docker-archive: destinations, in addition to the name:tag specified as destination, also add these
	removeSignatures         bool                      // Do not copy signatures from the source image
	signByFingerprint        string                    // Sign the image using a GPG key with the specified fingerprint
	signBySigstoreParamFile  string                    // Sign the image using a sigstore signature per configuration in a param file
	signBySigstorePrivateKey string                    // Sign the image using a sigstore private key
	signPassphraseFile       string                    // Path pointing to a passphrase file when signing (for either signature format, but only one of them)
	signIdentity             string                    // Identity of the signed image, must be a fully specified docker reference
	digestFile               string                    // Write digest to this file
	format                   commonFlag.OptionalString // Force conversion of the image to a specified format
	quiet                    bool                      // Suppress output information when copying images
	all                      bool                      // Copy all of the images if the source is a list
	multiArch                commonFlag.OptionalString // How to handle multi architecture images
	preserveDigests          bool                      // Preserve digests during copy
	encryptLayer             []int                     // The list of layers to encrypt
	encryptionKeys           []string                  // Keys needed to encrypt the image
	decryptionKeys           []string                  // Keys needed to decrypt the image
}

type deleteOptions struct {
	global    *globalOptions
	image     *imageOptions
	retryOpts *retry.Options
}

type inspectOptions struct {
	global        *globalOptions
	image         *imageOptions
	retryOpts     *retry.Options
	format        string
	raw           bool // Output the raw manifest instead of parsing information about the image
	config        bool // Output the raw config blob instead of parsing information about the image
	doNotListTags bool // Do not list all tags available in the same repository
}

type layersOptions struct {
	global    *globalOptions
	image     *imageOptions
	retryOpts *retry.Options
}

// tagListOutput is the output format of (skopeo list-tags), primarily so that we can format it with a simple json.MarshalIndent.
type tagListOutput struct {
	Repository string `json:",omitempty"`
	Tags       []string
}

type tagsOptions struct {
	global    *globalOptions
	image     *imageOptions
	retryOpts *retry.Options
}

type loginOptions struct {
	global    *globalOptions
	loginOpts auth.LoginOptions
	tlsVerify commonFlag.OptionalBool
}

type logoutOptions struct {
	global     *globalOptions
	logoutOpts auth.LogoutOptions
	tlsVerify  commonFlag.OptionalBool
}

type manifestDigestOptions struct {
}

type standaloneSignOptions struct {
	output         string // Output file path
	passphraseFile string // Path pointing to a passphrase file when signing
}

// syncOptions contains information retrieved from the skopeo sync command line.
type syncOptions struct {
	global                   *globalOptions // Global (not command dependent) skopeo options
	deprecatedTLSVerify      *deprecatedTLSVerifyOption
	srcImage                 *imageOptions     // Source image options
	destImage                *imageDestOptions // Destination image options
	retryOpts                *retry.Options
	removeSignatures         bool                      // Do not copy signatures from the source image
	signByFingerprint        string                    // Sign the image using a GPG key with the specified fingerprint
	signBySigstoreParamFile  string                    // Sign the image using a sigstore signature per configuration in a param file
	signBySigstorePrivateKey string                    // Sign the image using a sigstore private key
	signPassphraseFile       string                    // Path pointing to a passphrase file when signing
	format                   commonFlag.OptionalString // Force conversion of the image to a specified format
	source                   string                    // Source repository name
	destination              string                    // Destination registry name
	scoped                   bool                      // When true, namespace copied images at destination using the source repository name
	all                      bool                      // Copy all of the images if an image in the source is a list
	dryRun                   bool                      // Don't actually copy anything, just output what it would have done
	preserveDigests          bool                      // Preserve digests during sync
	keepGoing                bool                      // Whether or not to abort the sync if there are any errors during syncing the images
	appendSuffix             string                    // Suffix to append to destination image tag
}

// repoDescriptor contains information of a single repository used as a sync source.
type repoDescriptor struct {
	DirBasePath string                 // base path when source is 'dir'
	ImageRefs   []types.ImageReference // List of tagged image found for the repository
	Context     *types.SystemContext   // SystemContext for the sync command
}

type generateSigstoreKeyOptions struct {
	outputPrefix   string
	passphraseFile string
}

type standaloneVerifyOptions struct {
	publicKeyFile string
}

// WARNING: Do not use the contents of this for ANY security decisions,
// and be VERY CAREFUL about showing this information to humans in any way which suggest that these values “are probably” reliable.
// There is NO REASON to expect the values to be correct, or not intentionally misleading
// (including things like “✅ Verified by $authority”)
//
// The subcommand is undocumented, and it may be renamed or entirely disappear in the future.
type untrustedSignatureDumpOptions struct {
}

// imageDestOptions is a superset of imageOptions specialized for image destinations.
// Every user should call imageDestOptions.warnAboutIneffectiveOptions() as part of handling the CLI
type imageDestOptions struct {
	*imageOptions
	dirForceCompression         bool                   // Compress layers when saving to the dir: transport
	dirForceDecompression       bool                   // Decompress layers when saving to the dir: transport
	ociAcceptUncompressedLayers bool                   // Whether to accept uncompressed layers in the oci: transport
	compressionFormat           string                 // Format to use for the compression
	compressionLevel            commonFlag.OptionalInt // Level to use for the compression
	precomputeDigests           bool                   // Precompute digests to dedup layers when saving to the docker: transport
	imageDestFlagPrefix         string
}

// errorShouldDisplayUsage is a subtype of error used by command handlers to indicate that cli.ShowSubcommandHelp should be called.
type errorShouldDisplayUsage struct {
	error
}

// tlsVerifyConfig is an implementation of the Unmarshaler interface, used to
// customize the unmarshaling behaviour of the tls-verify YAML key.
type tlsVerifyConfig struct {
	skip types.OptionalBool // skip TLS verification check (false by default)
}

// registrySyncConfig contains information about a single registry, read from
// the source YAML file
type registrySyncConfig struct {
	Images           map[string][]string    // Images map images name to slices with the images' references (tags, digests)
	ImagesByTagRegex map[string]string      `yaml:"images-by-tag-regex"` // Images map images name to regular expression with the images' tags
	Credentials      types.DockerAuthConfig // Username and password used to authenticate with the registry
	TLSVerify        tlsVerifyConfig        `yaml:"tls-verify"` // TLS verification mode (enabled by default)
	CertDir          string                 `yaml:"cert-dir"`   // Path to the TLS certificates of the registry
}

// deprecatedTLSVerifyOption represents a deprecated --tls-verify option,
// which was accepted for all subcommands, for a time.
// Every user should call deprecatedTLSVerifyOption.warnIfUsed() as part of handling the CLI,
// whether or not the value actually ends up being used.
// DO NOT ADD ANY NEW USES OF THIS; just call dockerImageFlags with an appropriate, possibly empty, flagPrefix.
type deprecatedTLSVerifyOption struct {
	tlsVerify commonFlag.OptionalBool // FIXME FIXME: Warn if this is used, or even if it is ignored.
}

// sharedImageOptions collects CLI flags which are image-related, but do not change across images.
// This really should be a part of globalOptions, but that would break existing users of (skopeo copy --authfile=).
type sharedImageOptions struct {
	authFilePath string // Path to a */containers/auth.json
}

// dockerImageOptions collects CLI flags specific to the "docker" transport, which are
// the same across subcommands, but may be different for each image
// (e.g. may differ between the source and destination of a copy)
type dockerImageOptions struct {
	global              *globalOptions             // May be shared across several imageOptions instances.
	shared              *sharedImageOptions        // May be shared across several imageOptions instances.
	deprecatedTLSVerify *deprecatedTLSVerifyOption // May be shared across several imageOptions instances, or nil.
	authFilePath        commonFlag.OptionalString  // Path to a */containers/auth.json (prefixed version to override shared image option).
	credsOption         commonFlag.OptionalString  // username[:password] for accessing a registry
	userName            commonFlag.OptionalString  // username for accessing a registry
	password            commonFlag.OptionalString  // password for accessing a registry
	registryToken       commonFlag.OptionalString  // token to be used directly as a Bearer token when accessing the registry
	dockerCertPath      string                     // A directory using Docker-like *.{crt,cert,key} files for connecting to a registry or a daemon
	tlsVerify           commonFlag.OptionalBool    // Require HTTPS and verify certificates (for docker: and docker-daemon:)
	noCreds             bool                       // Access the registry anonymously
}

// imageOptions collects CLI flags which are the same across subcommands, but may be different for each image
// (e.g. may differ between the source and destination of a copy)
type imageOptions struct {
	dockerImageOptions
	sharedBlobDir    string // A directory to use for OCI blobs, shared across repositories
	dockerDaemonHost string // docker-daemon: host to connect to
}

// sourceConfig contains all registries information read from the source YAML file
type sourceConfig map[string]registrySyncConfig

type proxyOptions struct {
	global    *globalOptions
	imageOpts *imageOptions
	sockFd    int
}

// proxyHandler is the state associated with our socket.
type proxyHandler struct {
	// lock protects everything else in this structure.
	lock sync.Mutex
	// opts is CLI options
	opts   *proxyOptions
	sysctx *types.SystemContext
	cache  types.BlobInfoCache

	// imageSerial is a counter for open images
	imageSerial uint64
	// images holds our opened images
	images map[uint64]*openImage
	// activePipes maps from "pipeid" to a pipe + goroutine pair
	activePipes map[uint32]*activePipe
}

// convertedLayerInfo is the reduced form of the OCI type BlobInfo
// Used in the return value of GetLayerInfo
type convertedLayerInfo struct {
	Digest    digest.Digest `json:"digest"`
	Size      int64         `json:"size"`
	MediaType string        `json:"media_type"`
}
