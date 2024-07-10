package config

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

type Configuration struct {
	ID            int              `yaml:"id"`
	Name          string           `yaml:"name"`
	Configuration RemoteManagement `yaml:"configuration"`
}

type RemoteManagement struct {
	GeneralSettings     GeneralSettings     `yaml:"generalSettings"`
	Network             Network             `yaml:"network"`
	Authentication      Authentication      `yaml:"authentication"`
	TLS                 TLS                 `yaml:"tls"`
	Redirection         Redirection         `yaml:"redirection"`
	UserAccounts        UserAccounts        `yaml:"userAccounts"`
	EnterpriseAssistant EnterpriseAssistant `yaml:"enterpriseAssistant"`
	AMTSpecific         AMTSpecific         `yaml:"amtSpecific"`
	BMCSpecific         BMCSpecific         `yaml:"bmcSpecific"`
	DASHSpecific        DASHSpecific        `yaml:"dashSpecific"`
	RedfishSpecific     RedfishSpecific     `yaml:"redfishSpecific"`
}

type GeneralSettings struct {
	SharedFQDN              bool `yaml:"sharedFQDN"`
	NetworkInterfaceEnabled int  `yaml:"networkInterfaceEnabled"`
	PingResponseEnabled     bool `yaml:"pingResponseEnabled"`
}

type Network struct {
	Wired    Wired    `yaml:"wired"`
	Wireless Wireless `yaml:"wireless"`
}

type Wired struct {
	DHCPEnabled    bool   `yaml:"dhcpEnabled"`
	IPSyncEnabled  bool   `yaml:"ipSyncEnabled"`
	SharedStaticIP bool   `yaml:"sharedStaticIP"`
	IPAddress      string `yaml:"ipAddress"`
	SubnetMask     string `yaml:"subnetMask"`
	DefaultGateway string `yaml:"defaultGateway"`
	PrimaryDNS     string `yaml:"primaryDNS"`
	SecondaryDNS   string `yaml:"secondaryDNS"`
	Authentication string `yaml:"authentication"`
}

type Wireless struct {
	Profiles []string `yaml:"profiles"`
}

type Authentication struct {
	Profiles []string `yaml:"profiles"`
}

type TLS struct {
	MutualAuthentication bool     `yaml:"mutualAuthentication"`
	Enabled              bool     `yaml:"enabled"`
	TrustedCN            []string `yaml:"trustedCN"`
}

type Redirection struct {
	Enabled     bool     `yaml:"enabled"`
	Services    Services `yaml:"services"`
	UserConsent string   `yaml:"userConsent"`
}

type Services struct {
	KVM  bool `yaml:"kvm"`
	SOL  bool `yaml:"sol"`
	IDER bool `yaml:"ider"`
}

type UserAccounts struct {
	UserAccounts []string `yaml:"userAccounts"`
}

type EnterpriseAssistant struct {
	URL      string `yaml:"url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type AMTSpecific struct {
	ControlMode         string `yaml:"controlMode"`
	AdminPassword       string `yaml:"adminPassword"`
	ProvisioningCert    string `yaml:"provisioningCert"`
	ProvisioningCertPwd string `yaml:"provisioningCertPwd"`
	MEBXPassword        string `yaml:"mebxPassword"`
}

type BMCSpecific struct {
	AdminPassword string `yaml:"adminPassword"`
}

type DASHSpecific struct {
	AdminPassword string `yaml:"adminPassword"`
}

type RedfishSpecific struct {
	AdminPassword string `yaml:"adminPassword"`
}

func main() {
	config := Configuration{
		ID:   20,
		Name: "new Profile",
		Configuration: RemoteManagement{
			GeneralSettings: GeneralSettings{
				SharedFQDN:              false,
				NetworkInterfaceEnabled: 0,
				PingResponseEnabled:     false,
			},
			Network: Network{
				Wired: Wired{
					DHCPEnabled:    false,
					IPSyncEnabled:  false,
					SharedStaticIP: false,
					IPAddress:      "",
					SubnetMask:     "",
					DefaultGateway: "",
					PrimaryDNS:     "",
					SecondaryDNS:   "",
					Authentication: "",
				},
				Wireless: Wireless{
					Profiles: []string{},
				},
			},
			Authentication: Authentication{
				Profiles: []string{},
			},
			TLS: TLS{
				MutualAuthentication: false,
				Enabled:              false,
				TrustedCN:            []string{},
			},
			Redirection: Redirection{
				Enabled: false,
				Services: Services{
					KVM:  false,
					SOL:  false,
					IDER: false,
				},
				UserConsent: "",
			},
			UserAccounts: UserAccounts{
				UserAccounts: []string{},
			},
			EnterpriseAssistant: EnterpriseAssistant{
				URL:      "",
				Username: "",
				Password: "",
			},
			AMTSpecific: AMTSpecific{
				ControlMode:         "ccm",
				AdminPassword:       "P@ssw0rd",
				ProvisioningCert:    "",
				ProvisioningCertPwd: "",
				MEBXPassword:        "",
			},
			BMCSpecific: BMCSpecific{
				AdminPassword: "",
			},
			DASHSpecific: DASHSpecific{
				AdminPassword: "",
			},
			RedfishSpecific: RedfishSpecific{
				AdminPassword: "",
			},
		},
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
