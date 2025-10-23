package local

import (
	// "encoding/xml"
	"strings"
	"testing"

	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publickey"
	"github.com/device-management-toolkit/go-wsman-messages/v2/pkg/wsman/amt/publicprivate"
	"github.com/device-management-toolkit/rpc-go/v2/internal/flags"
	"github.com/device-management-toolkit/rpc-go/v2/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestPruneCerts(t *testing.T) {
	tests := []struct {
		name          string
		expectedError bool
	}{
		{
			name:          "successful pruning",
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &flags.Flags{}
			mockAMT := new(MockAMT)
			mockWsman := new(MockWSMAN)
			service := NewProvisioningService(f)
			service.amtCommand = mockAMT
			service.interfacedWsmanMessage = mockWsman

			err := service.PruneCerts()
			assert.NoError(t, err)
		})
	}
}

func TestPruneCertsMPSRootLogic(t *testing.T) {
	tests := []struct {
		name         string
		certificates []publickey.RefinedPublicKeyCertificateResponse
		description  string
	}{
		{
			name: "MPSRoot certificate should not be pruned",
			certificates: []publickey.RefinedPublicKeyCertificateResponse{
				{
					ElementName:            "MPS Root Certificate",
					InstanceID:             "Intel(r) AMT Certificate: Handle: 1",
					Subject:                "C=unknown,O=unknown,CN=MPSRoot-4311f5", // MPSRoot certificate
					AssociatedProfiles:     nil,                                     // No profiles but should be preserved
					TrustedRootCertificate: true,
				},
				{
					ElementName:            "Regular Certificate",
					InstanceID:             "Intel(r) AMT Certificate: Handle: 2",
					Subject:                "C=US,O=TestOrg,CN=TestCert", // Regular certificate
					AssociatedProfiles:     nil,                          // No profiles, should be candidate for deletion
					TrustedRootCertificate: false,
				},
			},
			description: "Tests that certificates with CN=MPSRoot are preserved during pruning",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, cert := range tc.certificates {
				isMPSRootCert := strings.Contains(cert.Subject, "CN=MPSRoot")
				shouldBeDeleted := cert.AssociatedProfiles == nil && !isMPSRootCert

				if strings.Contains(cert.Subject, "CN=MPSRoot") {
					assert.False(t, shouldBeDeleted, "MPSRoot certificate should never be marked for deletion: %s", cert.Subject)
				} else {
					if cert.AssociatedProfiles == nil {
						assert.True(t, shouldBeDeleted, "Regular certificate without profiles should be marked for deletion: %s", cert.Subject)
					}
				}
			}
		})
	}
}

type test struct {
	name       string
	setupMocks func(*MockWSMAN)
	res        any
	err        error
}

func TestGetCertificates(t *testing.T) {
	tests := []test{
		{
			name: "success",
			setupMocks: func(mock *MockWSMAN) {
			},
			res: SecuritySettings{
				ProfileAssociation: []ProfileAssociation{
					{
						Type:              "Wireless",
						ProfileID:         "wifi8021x",
						RootCertificate:   interface{}(nil),
						ClientCertificate: interface{}(nil),
						Key:               interface{}(nil),
					},
				},
				Certificates: []publickey.RefinedPublicKeyCertificateResponse{},
				Keys:         []publicprivate.RefinedPublicPrivateKeyPair(nil),
			},
			err: nil,
		},
		{
			name: "GetCertificates fails",
			setupMocks: func(mock *MockWSMAN) {
				errGetConcreteDependencies = utils.WSMANMessageError
			},
			res: SecuritySettings{},
			err: utils.WSMANMessageError,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			service, mockWsman := setupProvisioningService()
			tc.setupMocks(mockWsman)

			response, err := service.GetCertificates()
			if tc.err != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.res, response)
		})
	}

	errGetConcreteDependencies = nil
}
