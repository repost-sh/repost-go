package repost

import "fmt"

// Version is the SDK release version used by transport and telemetry product
// identification. Release automation keeps it aligned with the module tag.
const Version = "0.3.0"

// DescriptorFormatVersion is the descriptor-format version this runtime
// implements. Generated clients declare the version they were emitted for;
// [Runtime.Send] refuses a mismatch. Bumped only on a wire-breaking change to the
// descriptor contract (see sdk/conformance/CONTRACT.md and the
// conformance-vector freeze policy).
const DescriptorFormatVersion = 2

// AssertDescriptorVersion refuses a generated client whose descriptor format
// this runtime does not implement, with the concrete fix per direction.
func AssertDescriptorVersion(declared int) error {
	switch {
	case declared == DescriptorFormatVersion:
		return nil
	case declared > DescriptorFormatVersion:
		return fmt.Errorf(
			"repost: [UNSUPPORTED_DESCRIPTOR_VERSION] $: the generated client declares descriptor format %d, but this runtime implements %d; upgrade the runtime module github.com/repost-sh/repost-go",
			declared, DescriptorFormatVersion,
		)
	default:
		return fmt.Errorf(
			"repost: the generated client declares descriptor format %d, but this runtime implements %d; re-run `repost schema generate` with the current CLI",
			declared, DescriptorFormatVersion,
		)
	}
}
