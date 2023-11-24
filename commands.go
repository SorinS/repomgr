package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containers/common/pkg/auth"
	"github.com/containers/common/pkg/report"
	"github.com/containers/common/pkg/retry"
	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/directory"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/archive"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/blobinfocache"
	"github.com/containers/image/v5/pkg/cli"
	sigst "github.com/containers/image/v5/pkg/cli/sigstore"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/signature/signer"
	"github.com/containers/image/v5/signature/sigstore"
	"github.com/containers/image/v5/transports"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	encconfig "github.com/containers/ocicrypt/config"
	enchelpers "github.com/containers/ocicrypt/helpers"
	"github.com/containers/skopeo/cmd/skopeo/inspect"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var transportHandlers = map[string]func(ctx context.Context, sys *types.SystemContext, opts *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error){
	docker.Transport.Name():  listDockerRepoTags,
	archive.Transport.Name(): listDockerArchiveTags,
}

func (opts *inspectOptions) run(args []string, stdout io.Writer) (retErr error) {
	var (
		rawManifest []byte
		src         types.ImageSource
		imgInspect  *types.ImageInspectInfo
	)
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errors.New("Exactly one argument expected")
	}
	if opts.raw && opts.format != "" {
		return errors.New("raw output does not support format option")
	}
	imageName := args[0]

	if err := reexecIfNecessaryForImages(imageName); err != nil {
		return err
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	if err := retry.IfNecessary(ctx, func() error {
		src, err = parseImageSource(ctx, opts.image, imageName)
		return err
	}, opts.retryOpts); err != nil {
		return fmt.Errorf("Error parsing image name %q: %w", imageName, err)
	}

	defer func() {
		if err := src.Close(); err != nil {
			retErr = noteCloseFailure(retErr, "closing image", err)
		}
	}()

	if err := retry.IfNecessary(ctx, func() error {
		rawManifest, _, err = src.GetManifest(ctx, nil)
		return err
	}, opts.retryOpts); err != nil {
		return fmt.Errorf("Error retrieving manifest for image: %w", err)
	}

	if opts.raw && !opts.config {
		_, err := stdout.Write(rawManifest)
		if err != nil {
			return fmt.Errorf("Error writing manifest to standard output: %w", err)
		}

		return nil
	}

	img, err := image.FromUnparsedImage(ctx, sys, image.UnparsedInstance(src, nil))
	if err != nil {
		return fmt.Errorf("Error parsing manifest for image: %w", err)
	}

	if opts.config && opts.raw {
		var configBlob []byte
		if err := retry.IfNecessary(ctx, func() error {
			configBlob, err = img.ConfigBlob(ctx)
			return err
		}, opts.retryOpts); err != nil {
			return fmt.Errorf("Error reading configuration blob: %w", err)
		}
		_, err = stdout.Write(configBlob)
		if err != nil {
			return fmt.Errorf("Error writing configuration blob to standard output: %w", err)
		}
		return nil
	} else if opts.config {
		var config *v1.Image
		if err := retry.IfNecessary(ctx, func() error {
			config, err = img.OCIConfig(ctx)
			return err
		}, opts.retryOpts); err != nil {
			return fmt.Errorf("Error reading OCI-formatted configuration data: %w", err)
		}
		if err := opts.writeOutput(stdout, config); err != nil {
			return fmt.Errorf("Error writing OCI-formatted configuration data to standard output: %w", err)
		}
		return nil
	}

	if err := retry.IfNecessary(ctx, func() error {
		imgInspect, err = img.Inspect(ctx)
		return err
	}, opts.retryOpts); err != nil {
		return err
	}

	outputData := inspect.Output{
		Name: "", // Set below if DockerReference() is known
		Tag:  imgInspect.Tag,
		// Digest is set below.
		RepoTags:      []string{}, // Possibly overridden for docker.Transport.
		Created:       imgInspect.Created,
		DockerVersion: imgInspect.DockerVersion,
		Labels:        imgInspect.Labels,
		Architecture:  imgInspect.Architecture,
		Os:            imgInspect.Os,
		Layers:        imgInspect.Layers,
		LayersData:    imgInspect.LayersData,
		Env:           imgInspect.Env,
	}
	outputData.Digest, err = manifest.Digest(rawManifest)
	if err != nil {
		return fmt.Errorf("Error computing manifest digest: %w", err)
	}
	if dockerRef := img.Reference().DockerReference(); dockerRef != nil {
		outputData.Name = dockerRef.Name()
	}
	if !opts.doNotListTags && img.Reference().Transport() == docker.Transport {
		sys, err := opts.image.newSystemContext()
		if err != nil {
			return err
		}
		outputData.RepoTags, err = docker.GetRepositoryTags(ctx, sys, img.Reference())
		if err != nil {
			// Some registries may decide to block the "list all tags" endpoint;
			// gracefully allow the inspect to continue in this case:
			fatalFailure := true
			// - AWS ECR rejects it if the "ecr:ListImages" action is not allowed.
			//   https://github.com/containers/skopeo/issues/726
			var ec errcode.ErrorCoder
			if ok := errors.As(err, &ec); ok && ec.ErrorCode() == errcode.ErrorCodeDenied {
				fatalFailure = false
			}
			// - public.ecr.aws does not implement the endpoint at all, and fails with 404:
			//   https://github.com/containers/skopeo/issues/1230
			//   This is actually "code":"NOT_FOUND", and the parser doesn’t preserve that.
			//   So, also check the error text.
			if ok := errors.As(err, &ec); ok && ec.ErrorCode() == errcode.ErrorCodeUnknown {
				var e errcode.Error
				if ok := errors.As(err, &e); ok && e.Code == errcode.ErrorCodeUnknown && e.Message == "404 page not found" {
					fatalFailure = false
				}
			}
			if fatalFailure {
				return fmt.Errorf("Error determining repository tags: %w", err)
			}
			logrus.Warnf("Registry disallows tag list retrieval; skipping")
		}
	}
	return opts.writeOutput(stdout, outputData)
}

// writeOutput writes data depending on opts.format to stdout
func (opts *inspectOptions) writeOutput(stdout io.Writer, data any) error {
	if report.IsJSON(opts.format) || opts.format == "" {
		out, err := json.MarshalIndent(data, "", "    ")
		if err == nil {
			fmt.Fprintf(stdout, "%s\n", string(out))
		}
		return err
	}

	rpt, err := report.New(stdout, "skopeo inspect").Parse(report.OriginUser, opts.format)
	if err != nil {
		return err
	}
	defer rpt.Flush()
	return rpt.Execute([]any{data})
}

// parseMultiArch parses the list processing selection
// It returns the copy.ImageListSelection to use with image.Copy option
func parseMultiArch(multiArch string) (copy.ImageListSelection, error) {
	switch multiArch {
	case "system":
		return copy.CopySystemImage, nil
	case "all":
		return copy.CopyAllImages, nil
	// There is no CopyNoImages value in copy.ImageListSelection, but because we
	// don't provide an option to select a set of images to copy, we can use
	// CopySpecificImages.
	case "index-only":
		return copy.CopySpecificImages, nil
	// We don't expose CopySpecificImages other than index-only above, because
	// we currently don't provide an option to choose the images to copy. That
	// could be added in the future.
	default:
		return copy.CopySystemImage, fmt.Errorf("unknown multi-arch option %q. Choose one of the supported options: 'system', 'all', or 'index-only'", multiArch)
	}
}

func (opts *copyOptions) run(args []string, stdout io.Writer) (retErr error) {
	if len(args) != 2 {
		return errorShouldDisplayUsage{errors.New("Exactly two arguments expected")}
	}
	opts.deprecatedTLSVerify.warnIfUsed([]string{"--src-tls-verify", "--dest-tls-verify"})
	imageNames := args

	if err := reexecIfNecessaryForImages(imageNames...); err != nil {
		return err
	}

	policyContext, err := opts.global.getPolicyContext()
	if err != nil {
		return fmt.Errorf("Error loading trust policy: %v", err)
	}
	defer func() {
		if err := policyContext.Destroy(); err != nil {
			retErr = noteCloseFailure(retErr, "tearing down policy context", err)
		}
	}()

	srcRef, err := alltransports.ParseImageName(imageNames[0])
	if err != nil {
		return fmt.Errorf("Invalid source name %s: %v", imageNames[0], err)
	}
	destRef, err := alltransports.ParseImageName(imageNames[1])
	if err != nil {
		return fmt.Errorf("Invalid destination name %s: %v", imageNames[1], err)
	}

	sourceCtx, err := opts.srcImage.newSystemContext()
	if err != nil {
		return err
	}
	destinationCtx, err := opts.destImage.newSystemContext()
	if err != nil {
		return err
	}

	var manifestType string
	if opts.format.Present() {
		manifestType, err = parseManifestFormat(opts.format.Value())
		if err != nil {
			return err
		}
	}

	for _, image := range opts.additionalTags {
		ref, err := reference.ParseNormalizedNamed(image)
		if err != nil {
			return fmt.Errorf("error parsing additional-tag '%s': %v", image, err)
		}
		namedTagged, isNamedTagged := ref.(reference.NamedTagged)
		if !isNamedTagged {
			return fmt.Errorf("additional-tag '%s' must be a tagged reference", image)
		}
		destinationCtx.DockerArchiveAdditionalTags = append(destinationCtx.DockerArchiveAdditionalTags, namedTagged)
	}

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if opts.quiet {
		stdout = nil
	}

	imageListSelection := copy.CopySystemImage
	if opts.multiArch.Present() && opts.all {
		return fmt.Errorf("Cannot use --all and --multi-arch flags together")
	}
	if opts.multiArch.Present() {
		imageListSelection, err = parseMultiArch(opts.multiArch.Value())
		if err != nil {
			return err
		}
	}
	if opts.all {
		imageListSelection = copy.CopyAllImages
	}

	if len(opts.encryptionKeys) > 0 && len(opts.decryptionKeys) > 0 {
		return fmt.Errorf("--encryption-key and --decryption-key cannot be specified together")
	}

	var encLayers *[]int
	var encConfig *encconfig.EncryptConfig
	var decConfig *encconfig.DecryptConfig

	if len(opts.encryptLayer) > 0 && len(opts.encryptionKeys) == 0 {
		return fmt.Errorf("--encrypt-layer can only be used with --encryption-key")
	}

	if len(opts.encryptionKeys) > 0 {
		// encryption
		p := opts.encryptLayer
		encLayers = &p
		encryptionKeys := opts.encryptionKeys
		ecc, err := enchelpers.CreateCryptoConfig(encryptionKeys, []string{})
		if err != nil {
			return fmt.Errorf("Invalid encryption keys: %v", err)
		}
		cc := encconfig.CombineCryptoConfigs([]encconfig.CryptoConfig{ecc})
		encConfig = cc.EncryptConfig
	}

	if len(opts.decryptionKeys) > 0 {
		// decryption
		decryptionKeys := opts.decryptionKeys
		dcc, err := enchelpers.CreateCryptoConfig([]string{}, decryptionKeys)
		if err != nil {
			return fmt.Errorf("Invalid decryption keys: %v", err)
		}
		cc := encconfig.CombineCryptoConfigs([]encconfig.CryptoConfig{dcc})
		decConfig = cc.DecryptConfig
	}

	// c/image/copy.Image does allow creating both simple signing and sigstore signatures simultaneously,
	// with independent passphrases, but that would make the CLI probably too confusing.
	// For now, use the passphrase with either, but only one of them.
	if opts.signPassphraseFile != "" && opts.signByFingerprint != "" && opts.signBySigstorePrivateKey != "" {
		return fmt.Errorf("Only one of --sign-by and sign-by-sigstore-private-key can be used with sign-passphrase-file")
	}
	var passphrase string
	if opts.signPassphraseFile != "" {
		p, err := cli.ReadPassphraseFile(opts.signPassphraseFile)
		if err != nil {
			return err
		}
		passphrase = p
	} else if opts.signBySigstorePrivateKey != "" {
		p, err := promptForPassphrase(opts.signBySigstorePrivateKey, os.Stdin, os.Stdout)
		if err != nil {
			return err
		}
		passphrase = p
	} // opts.signByFingerprint triggers a GPG-agent passphrase prompt, possibly using a more secure channel, so we usually shouldn’t prompt ourselves if no passphrase was explicitly provided.

	var signers []*signer.Signer
	if opts.signBySigstoreParamFile != "" {
		signer, err := sigst.NewSignerFromParameterFile(opts.signBySigstoreParamFile, &sigst.Options{
			PrivateKeyPassphrasePrompt: func(keyFile string) (string, error) {
				return promptForPassphrase(keyFile, os.Stdin, os.Stdout)
			},
			Stdin:  os.Stdin,
			Stdout: stdout,
		})
		if err != nil {
			return fmt.Errorf("Error using --sign-by-sigstore: %w", err)
		}
		defer signer.Close()
		signers = append(signers, signer)
	}

	var signIdentity reference.Named = nil
	if opts.signIdentity != "" {
		signIdentity, err = reference.ParseNamed(opts.signIdentity)
		if err != nil {
			return fmt.Errorf("Could not parse --sign-identity: %v", err)
		}
	}

	opts.destImage.warnAboutIneffectiveOptions(destRef.Transport())

	return retry.IfNecessary(ctx, func() error {
		manifestBytes, err := copy.Image(ctx, policyContext, destRef, srcRef, &copy.Options{
			RemoveSignatures:                 opts.removeSignatures,
			Signers:                          signers,
			SignBy:                           opts.signByFingerprint,
			SignPassphrase:                   passphrase,
			SignBySigstorePrivateKeyFile:     opts.signBySigstorePrivateKey,
			SignSigstorePrivateKeyPassphrase: []byte(passphrase),
			SignIdentity:                     signIdentity,
			ReportWriter:                     stdout,
			SourceCtx:                        sourceCtx,
			DestinationCtx:                   destinationCtx,
			ForceManifestMIMEType:            manifestType,
			ImageListSelection:               imageListSelection,
			PreserveDigests:                  opts.preserveDigests,
			OciDecryptConfig:                 decConfig,
			OciEncryptLayers:                 encLayers,
			OciEncryptConfig:                 encConfig,
		})
		if err != nil {
			return err
		}
		if opts.digestFile != "" {
			manifestDigest, err := manifest.Digest(manifestBytes)
			if err != nil {
				return err
			}
			if err = os.WriteFile(opts.digestFile, []byte(manifestDigest.String()), 0644); err != nil {
				return fmt.Errorf("Failed to write digest to file %q: %w", opts.digestFile, err)
			}
		}
		return nil
	}, opts.retryOpts)
}

func (opts *deleteOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("Usage: delete imageReference")
	}
	imageName := args[0]

	if err := reexecIfNecessaryForImages(imageName); err != nil {
		return err
	}

	ref, err := alltransports.ParseImageName(imageName)
	if err != nil {
		return fmt.Errorf("Invalid source name %s: %v", imageName, err)
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	return retry.IfNecessary(ctx, func() error {
		return ref.DeleteImage(ctx, sys)
	}, opts.retryOpts)
}

// ensurePathDoesNotExist verifies that path does not refer to an existing file,
// and returns an error if so.
func ensurePathDoesNotExist(path string) error {
	switch _, err := os.Stat(path); {
	case err == nil:
		return fmt.Errorf("Refusing to overwrite existing %q", path)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("Error checking existence of %q: %w", path, err)
	}
}

func (opts *generateSigstoreKeyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 0 || opts.outputPrefix == "" {
		return errors.New("Usage: generate-sigstore-key --output-prefix PREFIX")
	}

	pubKeyPath := opts.outputPrefix + ".pub"
	privateKeyPath := opts.outputPrefix + ".private"
	if err := ensurePathDoesNotExist(pubKeyPath); err != nil {
		return err
	}
	if err := ensurePathDoesNotExist(privateKeyPath); err != nil {
		return err
	}

	var passphrase string
	if opts.passphraseFile != "" {
		p, err := cli.ReadPassphraseFile(opts.passphraseFile)
		if err != nil {
			return err
		}
		passphrase = p
	} else {
		p, err := promptForPassphrase(privateKeyPath, os.Stdin, os.Stdout)
		if err != nil {
			return err
		}
		passphrase = p
	}

	keys, err := sigstore.GenerateKeyPair([]byte(passphrase))
	if err != nil {
		return fmt.Errorf("Error generating key pair: %w", err)
	}

	if err := os.WriteFile(privateKeyPath, keys.PrivateKey, 0600); err != nil {
		return fmt.Errorf("Error writing private key to %q: %w", privateKeyPath, err)
	}
	if err := os.WriteFile(pubKeyPath, keys.PublicKey, 0644); err != nil {
		return fmt.Errorf("Error writing private key to %q: %w", pubKeyPath, err)
	}
	fmt.Fprintf(stdout, "Key written to %q and %q", privateKeyPath, pubKeyPath)
	return nil
}

func (opts *layersOptions) run(args []string, stdout io.Writer) (retErr error) {
	fmt.Fprintln(os.Stderr, `DEPRECATED: skopeo layers is deprecated in favor of skopeo copy`)
	if len(args) == 0 {
		return errors.New("Usage: layers imageReference [layer...]")
	}
	imageName := args[0]

	if err := reexecIfNecessaryForImages(imageName); err != nil {
		return err
	}

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}
	cache := blobinfocache.DefaultCache(sys)
	var (
		rawSource types.ImageSource
		src       types.ImageCloser
	)
	if err = retry.IfNecessary(ctx, func() error {
		rawSource, err = parseImageSource(ctx, opts.image, imageName)
		return err
	}, opts.retryOpts); err != nil {
		return err
	}
	if err = retry.IfNecessary(ctx, func() error {
		src, err = image.FromSource(ctx, sys, rawSource)
		return err
	}, opts.retryOpts); err != nil {
		if closeErr := rawSource.Close(); closeErr != nil {
			return fmt.Errorf("%w (closing image source: %v)", err, closeErr)
		}

		return err
	}
	defer func() {
		if err := src.Close(); err != nil {
			retErr = noteCloseFailure(retErr, "closing image", err)
		}
	}()

	type blobDigest struct {
		digest   digest.Digest
		isConfig bool
	}
	var blobDigests []blobDigest
	for _, dString := range args[1:] {
		if !strings.HasPrefix(dString, "sha256:") {
			dString = "sha256:" + dString
		}
		d, err := digest.Parse(dString)
		if err != nil {
			return err
		}
		blobDigests = append(blobDigests, blobDigest{digest: d, isConfig: false})
	}

	if len(blobDigests) == 0 {
		layers := src.LayerInfos()
		seenLayers := map[digest.Digest]struct{}{}
		for _, info := range layers {
			if _, ok := seenLayers[info.Digest]; !ok {
				blobDigests = append(blobDigests, blobDigest{digest: info.Digest, isConfig: false})
				seenLayers[info.Digest] = struct{}{}
			}
		}
		configInfo := src.ConfigInfo()
		if configInfo.Digest != "" {
			blobDigests = append(blobDigests, blobDigest{digest: configInfo.Digest, isConfig: true})
		}
	}

	tmpDir, err := os.MkdirTemp(".", "layers-")
	if err != nil {
		return err
	}
	tmpDirRef, err := directory.NewReference(tmpDir)
	if err != nil {
		return err
	}
	dest, err := tmpDirRef.NewImageDestination(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if err := dest.Close(); err != nil {
			retErr = noteCloseFailure(retErr, "closing destination", err)
		}
	}()

	for _, bd := range blobDigests {
		var (
			r        io.ReadCloser
			blobSize int64
		)
		if err = retry.IfNecessary(ctx, func() error {
			r, blobSize, err = rawSource.GetBlob(ctx, types.BlobInfo{Digest: bd.digest, Size: -1}, cache)
			return err
		}, opts.retryOpts); err != nil {
			return err
		}
		if _, err := dest.PutBlob(ctx, r, types.BlobInfo{Digest: bd.digest, Size: blobSize}, cache, bd.isConfig); err != nil {
			if closeErr := r.Close(); closeErr != nil {
				return fmt.Errorf("%w (close error: %v)", err, closeErr)
			}
			return err
		}
	}

	var manifest []byte
	if err = retry.IfNecessary(ctx, func() error {
		manifest, _, err = src.Manifest(ctx)
		return err
	}, opts.retryOpts); err != nil {
		return err
	}
	if err := dest.PutManifest(ctx, manifest, nil); err != nil {
		return err
	}

	return dest.Commit(ctx, image.UnparsedInstance(rawSource, nil))
}

func (opts *loginOptions) run(args []string, stdout io.Writer) error {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()
	opts.loginOpts.Stdout = stdout
	opts.loginOpts.Stdin = os.Stdin
	opts.loginOpts.AcceptRepositories = true
	sys := opts.global.newSystemContext()
	if opts.tlsVerify.Present() {
		sys.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.Value())
	}
	return auth.Login(ctx, sys, &opts.loginOpts, args)
}

func (opts *logoutOptions) run(args []string, stdout io.Writer) error {
	opts.logoutOpts.Stdout = stdout
	opts.logoutOpts.AcceptRepositories = true
	sys := opts.global.newSystemContext()
	if opts.tlsVerify.Present() {
		sys.DockerInsecureSkipTLSVerify = types.NewOptionalBool(!opts.tlsVerify.Value())
	}
	return auth.Logout(sys, &opts.logoutOpts, args)
}

func (opts *manifestDigestOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("Usage: skopeo manifest-digest manifest")
	}
	manifestPath := args[0]

	man, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %v", manifestPath, err)
	}
	digest, err := manifest.Digest(man)
	if err != nil {
		return fmt.Errorf("Error computing digest: %v", err)
	}
	fmt.Fprintf(stdout, "%s\n", digest)
	return nil
}

func (opts *standaloneVerifyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 4 {
		return errors.New("Usage: skopeo standalone-verify manifest docker-reference key-fingerprint signature")
	}
	manifestPath := args[0]
	expectedDockerReference := args[1]
	expectedFingerprints := strings.Split(args[2], ",")
	signaturePath := args[3]

	if opts.publicKeyFile == "" && len(expectedFingerprints) == 1 && expectedFingerprints[0] == "any" {
		return fmt.Errorf("Cannot use any fingerprint without a public key file")
	}
	unverifiedManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %w", manifestPath, err)
	}
	unverifiedSignature, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("Error reading signature from %s: %w", signaturePath, err)
	}

	var mech signature.SigningMechanism
	var publicKeyfingerprints []string
	if opts.publicKeyFile != "" {
		publicKeys, err := os.ReadFile(opts.publicKeyFile)
		if err != nil {
			return fmt.Errorf("Error reading public keys from %s: %w", opts.publicKeyFile, err)
		}
		mech, publicKeyfingerprints, err = signature.NewEphemeralGPGSigningMechanism(publicKeys)
		if err != nil {
			return fmt.Errorf("Error initializing GPG: %w", err)

		}
	} else {
		mech, err = signature.NewGPGSigningMechanism()
		if err != nil {
			return fmt.Errorf("Error initializing GPG: %w", err)
		}
	}
	defer mech.Close()

	if len(expectedFingerprints) == 1 && expectedFingerprints[0] == "any" {
		expectedFingerprints = publicKeyfingerprints
	}

	sig, verificationFingerprint, err := signature.VerifyImageManifestSignatureUsingKeyIdentityList(unverifiedSignature, unverifiedManifest, expectedDockerReference, mech, expectedFingerprints)
	if err != nil {
		return fmt.Errorf("Error verifying signature: %w", err)
	}

	fmt.Fprintf(stdout, "Signature verified using fingerprint %s, digest %s\n", verificationFingerprint, sig.DockerManifestDigest)
	return nil
}

func (opts *untrustedSignatureDumpOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("Usage: skopeo untrusted-signature-dump-without-verification signature")
	}
	untrustedSignaturePath := args[0]

	untrustedSignature, err := os.ReadFile(untrustedSignaturePath)
	if err != nil {
		return fmt.Errorf("Error reading untrusted signature from %s: %w", untrustedSignaturePath, err)
	}

	untrustedInfo, err := signature.GetUntrustedSignatureInformationWithoutVerifying(untrustedSignature)
	if err != nil {
		return fmt.Errorf("Error decoding untrusted signature: %v", err)
	}
	untrustedOut, err := json.MarshalIndent(untrustedInfo, "", "    ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(untrustedOut))
	return nil
}

func (opts *standaloneSignOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 3 || opts.output == "" {
		return errors.New("Usage: skopeo standalone-sign manifest docker-reference key-fingerprint -o signature")
	}
	manifestPath := args[0]
	dockerReference := args[1]
	fingerprint := args[2]

	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading %s: %w", manifestPath, err)
	}

	mech, err := signature.NewGPGSigningMechanism()
	if err != nil {
		return fmt.Errorf("Error initializing GPG: %w", err)
	}
	defer mech.Close()

	passphrase, err := cli.ReadPassphraseFile(opts.passphraseFile)
	if err != nil {
		return err
	}

	signature, err := signature.SignDockerManifestWithOptions(manifest, dockerReference, mech, fingerprint, &signature.SignOptions{Passphrase: passphrase})
	if err != nil {
		return fmt.Errorf("Error creating signature: %w", err)
	}

	if err := os.WriteFile(opts.output, signature, 0644); err != nil {
		return fmt.Errorf("Error writing signature to %s: %w", opts.output, err)
	}
	return nil
}

// UnmarshalYAML is the implementation of the Unmarshaler interface method
// for the tlsVerifyConfig type.
// It unmarshals the 'tls-verify' YAML key so that, when they key is not
// specified, tls verification is enforced.
func (tls *tlsVerifyConfig) UnmarshalYAML(value *yaml.Node) error {
	var verify bool
	if err := value.Decode(&verify); err != nil {
		return err
	}

	tls.skip = types.NewOptionalBool(!verify)
	return nil
}

// newSourceConfig unmarshals the provided YAML file path to the sourceConfig type.
// It returns a new unmarshaled sourceConfig object and any error encountered.
func newSourceConfig(yamlFile string) (sourceConfig, error) {
	var cfg sourceConfig
	source, err := os.ReadFile(yamlFile)
	if err != nil {
		return cfg, err
	}
	err = yaml.Unmarshal(source, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("Failed to unmarshal %q: %w", yamlFile, err)
	}
	return cfg, nil
}

// parseRepositoryReference parses input into a reference.Named, and verifies that it names a repository, not an image.
func parseRepositoryReference(input string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		return nil, err
	}
	if !reference.IsNameOnly(ref) {
		return nil, errors.New("input names a reference, not a repository")
	}
	return ref, nil
}

// destinationReference creates an image reference using the provided transport.
// It returns a image reference to be used as destination of an image copy and
// any error encountered.
func destinationReference(destination string, transport string) (types.ImageReference, error) {
	var imageTransport types.ImageTransport

	switch transport {
	case docker.Transport.Name():
		destination = fmt.Sprintf("//%s", destination)
		imageTransport = docker.Transport
	case directory.Transport.Name():
		_, err := os.Stat(destination)
		if err == nil {
			return nil, fmt.Errorf("Refusing to overwrite destination directory %q", destination)
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("Destination directory could not be used: %w", err)
		}
		// the directory holding the image must be created here
		if err = os.MkdirAll(destination, 0755); err != nil {
			return nil, fmt.Errorf("Error creating directory for image %s: %w", destination, err)
		}
		imageTransport = directory.Transport
	default:
		return nil, fmt.Errorf("%q is not a valid destination transport", transport)
	}
	logrus.Debugf("Destination for transport %q: %s", transport, destination)

	destRef, err := imageTransport.ParseReference(destination)
	if err != nil {
		return nil, fmt.Errorf("Cannot obtain a valid image reference for transport %q and reference %q: %w", imageTransport.Name(), destination, err)
	}

	return destRef, nil
}

// getImageTags lists all tags in a repository.
// It returns a string slice of tags and any error encountered.
func getImageTags(ctx context.Context, sysCtx *types.SystemContext, repoRef reference.Named) ([]string, error) {
	name := repoRef.Name()
	logrus.WithFields(logrus.Fields{
		"image": name,
	}).Info("Getting tags")
	// Ugly: NewReference rejects IsNameOnly references, and GetRepositoryTags ignores the tag/digest.
	// So, we use TagNameOnly here only to shut up NewReference
	dockerRef, err := docker.NewReference(reference.TagNameOnly(repoRef))
	if err != nil {
		return nil, err // Should never happen for a reference with tag and no digest
	}
	tags, err := docker.GetRepositoryTags(ctx, sysCtx, dockerRef)
	if err != nil {
		return nil, fmt.Errorf("Error determining repository tags for repo %s: %w", name, err)
	}

	return tags, nil
}

// imagesToCopyFromRepo builds a list of image references from the tags
// found in a source repository.
// It returns an image reference slice with as many elements as the tags found
// and any error encountered.
func imagesToCopyFromRepo(sys *types.SystemContext, repoRef reference.Named) ([]types.ImageReference, error) {
	tags, err := getImageTags(context.Background(), sys, repoRef)
	if err != nil {
		return nil, err
	}

	var sourceReferences []types.ImageReference
	for _, tag := range tags {
		taggedRef, err := reference.WithTag(repoRef, tag)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"repo": repoRef.Name(),
				"tag":  tag,
			}).Errorf("Error creating a tagged reference from registry tag list: %v", err)
			continue
		}
		ref, err := docker.NewReference(taggedRef)
		if err != nil {
			return nil, fmt.Errorf("Cannot obtain a valid image reference for transport %q and reference %s: %w", docker.Transport.Name(), taggedRef.String(), err)
		}
		sourceReferences = append(sourceReferences, ref)
	}
	return sourceReferences, nil
}

// imagesToCopyFromDir builds a list of image references from the images found
// in the source directory.
// It returns an image reference slice with as many elements as the images found
// and any error encountered.
func imagesToCopyFromDir(dirPath string) ([]types.ImageReference, error) {
	var sourceReferences []types.ImageReference
	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "manifest.json" {
			dirname := filepath.Dir(path)
			ref, err := directory.Transport.ParseReference(dirname)
			if err != nil {
				return fmt.Errorf("Cannot obtain a valid image reference for transport %q and reference %q: %w", directory.Transport.Name(), dirname, err)
			}
			sourceReferences = append(sourceReferences, ref)
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil {
		return sourceReferences,
			fmt.Errorf("Error walking the path %q: %w", dirPath, err)
	}

	return sourceReferences, nil
}

// imagesToCopyFromRegistry builds a list of repository descriptors from the images
// in a registry configuration.
// It returns a repository descriptors slice with as many elements as the images
// found and any error encountered. Each element of the slice is a list of
// image references, to be used as sync source.
func imagesToCopyFromRegistry(registryName string, cfg registrySyncConfig, sourceCtx types.SystemContext) ([]repoDescriptor, error) {
	serverCtx := &sourceCtx
	// override ctx with per-registryName options
	serverCtx.DockerCertPath = cfg.CertDir
	serverCtx.DockerDaemonCertPath = cfg.CertDir
	serverCtx.DockerDaemonInsecureSkipTLSVerify = (cfg.TLSVerify.skip == types.OptionalBoolTrue)
	serverCtx.DockerInsecureSkipTLSVerify = cfg.TLSVerify.skip
	if cfg.Credentials != (types.DockerAuthConfig{}) {
		serverCtx.DockerAuthConfig = &cfg.Credentials
	}
	var repoDescList []repoDescriptor
	for imageName, refs := range cfg.Images {
		repoLogger := logrus.WithFields(logrus.Fields{
			"repo":     imageName,
			"registry": registryName,
		})
		repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, imageName))
		if err != nil {
			repoLogger.Error("Error parsing repository name, skipping")
			logrus.Error(err)
			continue
		}

		repoLogger.Info("Processing repo")

		var sourceReferences []types.ImageReference
		if len(refs) != 0 {
			for _, ref := range refs {
				tagLogger := logrus.WithFields(logrus.Fields{"ref": ref})
				var named reference.Named
				// first try as digest
				if d, err := digest.Parse(ref); err == nil {
					named, err = reference.WithDigest(repoRef, d)
					if err != nil {
						tagLogger.Error("Error processing ref, skipping")
						logrus.Error(err)
						continue
					}
				} else {
					tagLogger.Debugf("Ref was not a digest, trying as a tag: %s", err)
					named, err = reference.WithTag(repoRef, ref)
					if err != nil {
						tagLogger.Error("Error parsing ref, skipping")
						logrus.Error(err)
						continue
					}
				}

				imageRef, err := docker.NewReference(named)
				if err != nil {
					tagLogger.Error("Error processing ref, skipping")
					logrus.Errorf("Error getting image reference: %s", err)
					continue
				}
				sourceReferences = append(sourceReferences, imageRef)
			}
		} else { // len(refs) == 0
			repoLogger.Info("Querying registry for image tags")
			sourceReferences, err = imagesToCopyFromRepo(serverCtx, repoRef)
			if err != nil {
				repoLogger.Error("Error processing repo, skipping")
				logrus.Error(err)
				continue
			}
		}

		if len(sourceReferences) == 0 {
			repoLogger.Warnf("No refs to sync found")
			continue
		}
		repoDescList = append(repoDescList, repoDescriptor{
			ImageRefs: sourceReferences,
			Context:   serverCtx})
	}

	for imageName, tagRegex := range cfg.ImagesByTagRegex {
		repoLogger := logrus.WithFields(logrus.Fields{
			"repo":     imageName,
			"registry": registryName,
		})
		repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", registryName, imageName))
		if err != nil {
			repoLogger.Error("Error parsing repository name, skipping")
			logrus.Error(err)
			continue
		}

		repoLogger.Info("Processing repo")

		var sourceReferences []types.ImageReference

		tagReg, err := regexp.Compile(tagRegex)
		if err != nil {
			repoLogger.WithFields(logrus.Fields{
				"regex": tagRegex,
			}).Error("Error parsing regex, skipping")
			logrus.Error(err)
			continue
		}

		repoLogger.Info("Querying registry for image tags")
		allSourceReferences, err := imagesToCopyFromRepo(serverCtx, repoRef)
		if err != nil {
			repoLogger.Error("Error processing repo, skipping")
			logrus.Error(err)
			continue
		}

		repoLogger.Infof("Start filtering using the regular expression: %v", tagRegex)
		for _, sReference := range allSourceReferences {
			tagged, isTagged := sReference.DockerReference().(reference.Tagged)
			if !isTagged {
				repoLogger.Errorf("Internal error, reference %s does not have a tag, skipping", sReference.DockerReference())
				continue
			}
			if tagReg.MatchString(tagged.Tag()) {
				sourceReferences = append(sourceReferences, sReference)
			}
		}

		if len(sourceReferences) == 0 {
			repoLogger.Warnf("No refs to sync found")
			continue
		}
		repoDescList = append(repoDescList, repoDescriptor{
			ImageRefs: sourceReferences,
			Context:   serverCtx})
	}

	return repoDescList, nil
}

// imagesToCopy retrieves all the images to copy from a specified sync source
// and transport.
// It returns a slice of repository descriptors, where each descriptor is a
// list of tagged image references to be used as sync source, and any error
// encountered.
func imagesToCopy(source string, transport string, sourceCtx *types.SystemContext) ([]repoDescriptor, error) {
	var descriptors []repoDescriptor

	switch transport {
	case docker.Transport.Name():
		desc := repoDescriptor{
			Context: sourceCtx,
		}
		named, err := reference.ParseNormalizedNamed(source) // May be a repository or an image.
		if err != nil {
			return nil, fmt.Errorf("Cannot obtain a valid image reference for transport %q and reference %q: %w", docker.Transport.Name(), source, err)
		}
		imageTagged := !reference.IsNameOnly(named)
		logrus.WithFields(logrus.Fields{
			"imagename": source,
			"tagged":    imageTagged,
		}).Info("Tag presence check")
		if imageTagged {
			srcRef, err := docker.NewReference(named)
			if err != nil {
				return nil, fmt.Errorf("Cannot obtain a valid image reference for transport %q and reference %q: %w", docker.Transport.Name(), named.String(), err)
			}
			desc.ImageRefs = []types.ImageReference{srcRef}
		} else {
			desc.ImageRefs, err = imagesToCopyFromRepo(sourceCtx, named)
			if err != nil {
				return descriptors, err
			}
			if len(desc.ImageRefs) == 0 {
				return descriptors, fmt.Errorf("No images to sync found in %q", source)
			}
		}
		descriptors = append(descriptors, desc)

	case directory.Transport.Name():
		desc := repoDescriptor{
			Context: sourceCtx,
		}

		if _, err := os.Stat(source); err != nil {
			return descriptors, fmt.Errorf("Invalid source directory specified: %w", err)
		}
		desc.DirBasePath = source
		var err error
		desc.ImageRefs, err = imagesToCopyFromDir(source)
		if err != nil {
			return descriptors, err
		}
		if len(desc.ImageRefs) == 0 {
			return descriptors, fmt.Errorf("No images to sync found in %q", source)
		}
		descriptors = append(descriptors, desc)

	case "yaml":
		cfg, err := newSourceConfig(source)
		if err != nil {
			return descriptors, err
		}
		for registryName, registryConfig := range cfg {
			if len(registryConfig.Images) == 0 && len(registryConfig.ImagesByTagRegex) == 0 {
				logrus.WithFields(logrus.Fields{
					"registry": registryName,
				}).Warn("No images specified for registry")
				continue
			}

			descs, err := imagesToCopyFromRegistry(registryName, registryConfig, *sourceCtx)
			if err != nil {
				return descriptors, fmt.Errorf("Failed to retrieve list of images from registry %q: %w", registryName, err)
			}
			descriptors = append(descriptors, descs...)
		}
	}

	return descriptors, nil
}

func (opts *syncOptions) run(args []string, stdout io.Writer) (retErr error) {
	if len(args) != 2 {
		return errorShouldDisplayUsage{errors.New("Exactly two arguments expected")}
	}
	opts.deprecatedTLSVerify.warnIfUsed([]string{"--src-tls-verify", "--dest-tls-verify"})

	policyContext, err := opts.global.getPolicyContext()
	if err != nil {
		return fmt.Errorf("Error loading trust policy: %w", err)
	}
	defer func() {
		if err := policyContext.Destroy(); err != nil {
			retErr = noteCloseFailure(retErr, "tearing down policy context", err)
		}
	}()

	// validate source and destination options
	if len(opts.source) == 0 {
		return errors.New("A source transport must be specified")
	}
	if !slices.Contains([]string{docker.Transport.Name(), directory.Transport.Name(), "yaml"}, opts.source) {
		return fmt.Errorf("%q is not a valid source transport", opts.source)
	}

	if len(opts.destination) == 0 {
		return errors.New("A destination transport must be specified")
	}
	if !slices.Contains([]string{docker.Transport.Name(), directory.Transport.Name()}, opts.destination) {
		return fmt.Errorf("%q is not a valid destination transport", opts.destination)
	}

	if opts.source == opts.destination && opts.source == directory.Transport.Name() {
		return errors.New("sync from 'dir' to 'dir' not implemented, consider using rsync instead")
	}

	opts.destImage.warnAboutIneffectiveOptions(transports.Get(opts.destination))

	imageListSelection := copy.CopySystemImage
	if opts.all {
		imageListSelection = copy.CopyAllImages
	}

	sourceCtx, err := opts.srcImage.newSystemContext()
	if err != nil {
		return err
	}

	var manifestType string
	if opts.format.Present() {
		manifestType, err = parseManifestFormat(opts.format.Value())
		if err != nil {
			return err
		}
	}

	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	sourceArg := args[0]
	var srcRepoList []repoDescriptor
	if err = retry.IfNecessary(ctx, func() error {
		srcRepoList, err = imagesToCopy(sourceArg, opts.source, sourceCtx)
		return err
	}, opts.retryOpts); err != nil {
		return err
	}

	destination := args[1]
	destinationCtx, err := opts.destImage.newSystemContext()
	if err != nil {
		return err
	}

	// c/image/copy.Image does allow creating both simple signing and sigstore signatures simultaneously,
	// with independent passphrases, but that would make the CLI probably too confusing.
	// For now, use the passphrase with either, but only one of them.
	if opts.signPassphraseFile != "" && opts.signByFingerprint != "" && opts.signBySigstorePrivateKey != "" {
		return fmt.Errorf("Only one of --sign-by and sign-by-sigstore-private-key can be used with sign-passphrase-file")
	}
	var passphrase string
	if opts.signPassphraseFile != "" {
		p, err := cli.ReadPassphraseFile(opts.signPassphraseFile)
		if err != nil {
			return err
		}
		passphrase = p
	} else if opts.signBySigstorePrivateKey != "" {
		p, err := promptForPassphrase(opts.signBySigstorePrivateKey, os.Stdin, os.Stdout)
		if err != nil {
			return err
		}
		passphrase = p
	}

	var signers []*signer.Signer
	if opts.signBySigstoreParamFile != "" {
		signer, err := sigst.NewSignerFromParameterFile(opts.signBySigstoreParamFile, &sigst.Options{
			PrivateKeyPassphrasePrompt: func(keyFile string) (string, error) {
				return promptForPassphrase(keyFile, os.Stdin, os.Stdout)
			},
			Stdin:  os.Stdin,
			Stdout: stdout,
		})
		if err != nil {
			return fmt.Errorf("Error using --sign-by-sigstore: %w", err)
		}
		defer signer.Close()
		signers = append(signers, signer)
	}

	options := copy.Options{
		RemoveSignatures:                      opts.removeSignatures,
		Signers:                               signers,
		SignBy:                                opts.signByFingerprint,
		SignPassphrase:                        passphrase,
		SignBySigstorePrivateKeyFile:          opts.signBySigstorePrivateKey,
		SignSigstorePrivateKeyPassphrase:      []byte(passphrase),
		ReportWriter:                          stdout,
		DestinationCtx:                        destinationCtx,
		ImageListSelection:                    imageListSelection,
		PreserveDigests:                       opts.preserveDigests,
		OptimizeDestinationImageAlreadyExists: true,
		ForceManifestMIMEType:                 manifestType,
	}
	errorsPresent := false
	imagesNumber := 0
	if opts.dryRun {
		logrus.Warn("Running in dry-run mode")
	}

	for _, srcRepo := range srcRepoList {
		options.SourceCtx = srcRepo.Context
		for counter, ref := range srcRepo.ImageRefs {
			var destSuffix string
			switch ref.Transport() {
			case docker.Transport:
				// docker -> dir or docker -> docker
				destSuffix = ref.DockerReference().String()
			case directory.Transport:
				// dir -> docker (we don't allow `dir` -> `dir` sync operations)
				destSuffix = strings.TrimPrefix(ref.StringWithinTransport(), srcRepo.DirBasePath)
				if destSuffix == "" {
					// if source is a full path to an image, have destPath scoped to repo:tag
					destSuffix = path.Base(srcRepo.DirBasePath)
				}
			}

			if !opts.scoped {
				destSuffix = path.Base(destSuffix)
			}

			destRef, err := destinationReference(path.Join(destination, destSuffix)+opts.appendSuffix, opts.destination)
			if err != nil {
				return err
			}

			fromToFields := logrus.Fields{
				"from": transports.ImageName(ref),
				"to":   transports.ImageName(destRef),
			}
			if opts.dryRun {
				logrus.WithFields(fromToFields).Infof("Would have copied image ref %d/%d", counter+1, len(srcRepo.ImageRefs))
			} else {
				logrus.WithFields(fromToFields).Infof("Copying image ref %d/%d", counter+1, len(srcRepo.ImageRefs))
				if err = retry.IfNecessary(ctx, func() error {
					_, err = copy.Image(ctx, policyContext, destRef, ref, &options)
					return err
				}, opts.retryOpts); err != nil {
					if !opts.keepGoing {
						return fmt.Errorf("Error copying ref %q: %w", transports.ImageName(ref), err)
					}
					// log the error, keep a note that there was a failure and move on to the next
					// image ref
					errorsPresent = true
					logrus.WithError(err).Errorf("Error copying ref %q", transports.ImageName(ref))
					continue
				}
			}
			imagesNumber++
		}
	}

	if opts.dryRun {
		logrus.Infof("Would have synced %d images from %d sources", imagesNumber, len(srcRepoList))
	} else {
		logrus.Infof("Synced %d images from %d sources", imagesNumber, len(srcRepoList))
	}
	if !errorsPresent {
		return nil
	}
	return errors.New("Sync failed due to previous reported error(s) for one or more images")
}

// supportedTransports returns all the supported transports
func supportedTransports(joinStr string) string {
	res := maps.Keys(transportHandlers)
	sort.Strings(res)
	return strings.Join(res, joinStr)
}

// Customized version of the alltransports.ParseImageName and docker.ParseReference that does not place a default tag in the reference
// Would really love to not have this, but needed to enforce tag-less and digest-less names
func parseDockerRepositoryReference(refString string) (types.ImageReference, error) {
	if !strings.HasPrefix(refString, docker.Transport.Name()+"://") {
		return nil, fmt.Errorf("docker: image reference %s does not start with %s://", refString, docker.Transport.Name())
	}

	_, dockerImageName, hasColon := strings.Cut(refString, ":")
	if !hasColon {
		return nil, fmt.Errorf(`Invalid image name "%s", expected colon-separated transport:reference`, refString)
	}

	ref, err := reference.ParseNormalizedNamed(strings.TrimPrefix(dockerImageName, "//"))
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, errors.New(`No tag or digest allowed in reference`)
	}

	// Checks ok, now return a reference. This is a hack because the tag listing code expects a full image reference even though the tag is ignored
	return docker.NewReference(reference.TagNameOnly(ref))
}

// List the tags from a repository contained in the imgRef reference. Any tag value in the reference is ignored
func listDockerTags(ctx context.Context, sys *types.SystemContext, imgRef types.ImageReference) (string, []string, error) {
	repositoryName := imgRef.DockerReference().Name()

	tags, err := docker.GetRepositoryTags(ctx, sys, imgRef)
	if err != nil {
		return ``, nil, fmt.Errorf("Error listing repository tags: %w", err)
	}
	return repositoryName, tags, nil
}

// return the tagLists from a docker repo
func listDockerRepoTags(ctx context.Context, sys *types.SystemContext, opts *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error) {
	// Do transport-specific parsing and validation to get an image reference
	imgRef, err := parseDockerRepositoryReference(userInput)
	if err != nil {
		return
	}
	if err = retry.IfNecessary(ctx, func() error {
		repositoryName, tagListing, err = listDockerTags(ctx, sys, imgRef)
		return err
	}, opts.retryOpts); err != nil {
		return
	}
	return
}

// return the tagLists from a docker archive file
func listDockerArchiveTags(_ context.Context, sys *types.SystemContext, _ *tagsOptions, userInput string) (repositoryName string, tagListing []string, err error) {
	ref, err := alltransports.ParseImageName(userInput)
	if err != nil {
		return
	}

	tarReader, _, err := archive.NewReaderForReference(sys, ref)
	if err != nil {
		return
	}
	defer tarReader.Close()

	imageRefs, err := tarReader.List()
	if err != nil {
		return
	}

	var repoTags []string
	for imageIndex, items := range imageRefs {
		for _, ref := range items {
			repoTags, err = tarReader.ManifestTagsForReference(ref)
			if err != nil {
				return
			}
			// handle for each untagged image
			if len(repoTags) == 0 {
				repoTags = []string{fmt.Sprintf("@%d", imageIndex)}
			}
			tagListing = append(tagListing, repoTags...)
		}
	}

	return
}

func (opts *tagsOptions) run(args []string, stdout io.Writer) (retErr error) {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 1 {
		return errorShouldDisplayUsage{errors.New("Exactly one non-option argument expected")}
	}

	sys, err := opts.image.newSystemContext()
	if err != nil {
		return err
	}

	transport := alltransports.TransportFromImageName(args[0])
	if transport == nil {
		return fmt.Errorf("Invalid %q: does not specify a transport", args[0])
	}

	var repositoryName string
	var tagListing []string

	if val, ok := transportHandlers[transport.Name()]; ok {
		repositoryName, tagListing, err = val(ctx, sys, opts, args[0])
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Unsupported transport '%s' for tag listing. Only supported: %s",
			transport.Name(), supportedTransports(", "))
	}

	outputData := tagListOutput{
		Repository: repositoryName,
		Tags:       tagListing,
	}

	out, err := json.MarshalIndent(outputData, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s\n", string(out))

	return err
}

// Implementation of podman experimental-image-proxy
func (opts *proxyOptions) run(args []string, stdout io.Writer) error {
	handler := &proxyHandler{
		opts:        opts,
		images:      make(map[uint64]*openImage),
		activePipes: make(map[uint32]*activePipe),
	}
	defer handler.close()

	// Convert the socket FD passed by client into a net.FileConn
	fd := os.NewFile(uintptr(opts.sockFd), "sock")
	fconn, err := net.FileConn(fd)
	if err != nil {
		return err
	}
	conn := fconn.(*net.UnixConn)

	// Allocate a buffer to copy the packet into
	buf := make([]byte, maxMsgSize)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading socket: %v", err)
		}
		readbuf := buf[0:n]

		rb, terminate, err := handler.processRequest(readbuf)
		if terminate {
			return nil
		}

		if err := rb.send(conn, err); err != nil {
			return fmt.Errorf("writing to socket: %w", err)
		}
	}
}
