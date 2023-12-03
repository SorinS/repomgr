package hashicorp

import "time"

// Secret is the structure returned for every secret within Vault.
type Secret struct {
	// The request ID that generated this response
	RequestID string `json:"request_id"`

	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`

	// Data is the actual contents of the secret. The format of the data
	// is arbitrary and up to the secret backend.
	Data map[string]interface{} `json:"data"`

	// Warnings contains any warnings related to the operation. These
	// are not issues that caused the command to fail, but that the
	// client should be aware of.
	Warnings []string `json:"warnings"`

	// Auth, if non-nil, means that there was authentication information
	// attached to this response.
	Auth *SecretAuth `json:"auth,omitempty"`

	// WrapInfo, if non-nil, means that the initial response was wrapped in the
	// cubbyhole of the given token (which has a TTL of the given number of
	// seconds)
	WrapInfo *SecretWrapInfo `json:"wrap_info,omitempty"`

	// MountType, if non-empty, provides some information about what kind
	// of mount this secret came from.
	MountType string `json:"mount_type,omitempty"`
}

// SecretWrapInfo contains wrapping information if we have it. If what is
// contained is an authentication token, the accessor for the token will be
// available in WrappedAccessor.
type SecretWrapInfo struct {
	Token           string    `json:"token"`
	Accessor        string    `json:"accessor"`
	TTL             int       `json:"ttl"`
	CreationTime    time.Time `json:"creation_time"`
	CreationPath    string    `json:"creation_path"`
	WrappedAccessor string    `json:"wrapped_accessor"`
}

// SecretAuth is the structure containing auth information if we have it.
type SecretAuth struct {
	ClientToken      string            `json:"client_token"`
	Accessor         string            `json:"accessor"`
	Policies         []string          `json:"policies"`
	TokenPolicies    []string          `json:"token_policies"`
	IdentityPolicies []string          `json:"identity_policies"`
	Metadata         map[string]string `json:"metadata"`
	Orphan           bool              `json:"orphan"`
	EntityID         string            `json:"entity_id"`

	LeaseDuration int  `json:"lease_duration"`
	Renewable     bool `json:"renewable"`

	MFARequirement *MFARequirement `json:"mfa_requirement"`
}

type MFARequirement struct {
	MFARequestID   string                       `json:"mfa_request_id,omitempty"`
	MFAConstraints map[string]*MFAConstraintAny `json:"mfa_constraints,omitempty"`
}

type MFAConstraintAny struct {
	Any []*MFAMethodID `json:"any,omitempty"`
}

type MFAMethodID struct {
	Type         string `json:"type,omitempty"`
	ID           string `json:"id,omitempty"`
	UsesPasscode bool   `json:"uses_passcode,omitempty"`
	Name         string `json:"name,omitempty"`
}
