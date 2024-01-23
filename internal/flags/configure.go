package flags

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"rpc/internal/config"
	"rpc/pkg/utils"

	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman/cim/wifi"
	"github.com/open-amt-cloud-toolkit/go-wsman-messages/pkg/wsman/ips/ieee8021x"

	"github.com/ilyakaznacheev/cleanenv"
	log "github.com/sirupsen/logrus"
)

func (f *Flags) printConfigurationUsage() string {
	executable := filepath.Base(os.Args[0])
	usage := "\nRemote Provisioning Client (RPC) - used for activation, deactivation, maintenance and status of AMT\n\n"
	usage = usage + "Usage: " + executable + " configure COMMAND [OPTIONS]\n\n"
	usage = usage + "Supported Configuration Commands:\n"
	usage = usage + "  addwifisettings Add or modify WiFi settings in AMT. AMT password is required. A config.yml or command line flags must be provided for all settings. This command runs without cloud interaction.\n"
	usage = usage + "                 Example: " + executable + " configure addwifisettings -password YourAMTPassword -config wificonfig.yaml\n"
	usage = usage + "  enablewifiport  Enables WiFi port and local profile synchronization settings in AMT. AMT password is required.\n"
	usage = usage + "                 Example: " + executable + " configure enablewifiport -password YourAMTPassword\n"
	usage = usage + "\nRun '" + executable + " configure COMMAND -h' for more information on a command.\n"
	fmt.Println(usage)
	return usage
}

func (f *Flags) handleConfigureCommand() error {
	if len(f.commandLineArgs) == 2 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	var err error

	f.SubCommand = f.commandLineArgs[2]
	switch f.SubCommand {
	case "addwifisettings":
		err = f.handleAddWifiSettings()
	case "enablewifiport":
		err = f.handleEnableWifiPort()
	default:
		f.printConfigurationUsage()
		err = utils.IncorrectCommandLineParameters
	}
	if err != nil {
		return err
	}

	f.Local = true
	if f.Password == "" {
		if f.LocalConfig.Password != "" {
			f.Password = f.LocalConfig.Password
		} else {
			if _, err = f.ReadPasswordFromUser(); err != nil {
				return utils.MissingOrIncorrectPassword
			}
			f.LocalConfig.Password = f.Password
		}
	} else {
		if f.LocalConfig.Password == "" {
			f.LocalConfig.Password = f.Password
		} else if f.LocalConfig.Password != f.Password {
			log.Error("password does not match config file password")
			return utils.MissingOrIncorrectPassword
		}
	}
	return nil
}

func (f *Flags) handleEnableWifiPort() error {
	var err error
	// var rc error
	if len(f.commandLineArgs) > 5 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	f.flagSetEnableWifiPort.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetEnableWifiPort.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetEnableWifiPort.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetEnableWifiPort.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")

	if err = f.flagSetEnableWifiPort.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	return nil
}

func (f *Flags) handleAddWifiSettings() error {
	var err error
	var secretsFilePath string
	if len(f.commandLineArgs) == 3 {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}
	var wifiSecretConfig config.SecretConfig
	var configJson string
	f.flagSetAddWifiSettings.BoolVar(&f.Verbose, "v", false, "Verbose output")
	f.flagSetAddWifiSettings.StringVar(&f.LogLevel, "l", "info", "Log level (panic,fatal,error,warn,info,debug,trace)")
	f.flagSetAddWifiSettings.BoolVar(&f.JsonOutput, "json", false, "JSON output")
	f.flagSetAddWifiSettings.StringVar(&f.Password, "password", f.lookupEnvOrString("AMT_PASSWORD", ""), "AMT password")
	f.flagSetAddWifiSettings.StringVar(&f.configContent, "config", "", "specify a config file or smb: file share URL")
	f.flagSetAddWifiSettings.StringVar(&configJson, "configJson", "", "configuration as a JSON string")
	f.flagSetAddWifiSettings.StringVar(&secretsFilePath, "secrets", "", "specify a secrets file ")
	// Params for entering a single wifi config from command line
	wifiCfg := config.WifiConfig{}
	ieee8021xCfg := config.Ieee8021xConfig{}
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.ProfileName, "profileName", "", "specify wifi profile name name")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.AuthenticationMethod, "authenticationMethod", 0, "specify authentication method")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.EncryptionMethod, "encryptionMethod", 0, "specify encryption method")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.SSID, "ssid", "", "specify ssid")
	f.flagSetAddWifiSettings.StringVar(&wifiCfg.PskPassphrase, "pskPassphrase", f.lookupEnvOrString("PSK_PASSPHRASE", ""), "specify psk passphrase")
	f.flagSetAddWifiSettings.IntVar(&wifiCfg.Priority, "priority", 0, "specify priority")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Username, "username", "", "specify username")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.Password, "ieee8021xPassword", f.lookupEnvOrString("IEE8021X_PASSWORD", ""), "8021x password if authenticationProtocol is PEAPv0/EAP-MSCHAPv2(2)")
	f.flagSetAddWifiSettings.IntVar(&ieee8021xCfg.AuthenticationProtocol, "authenticationProtocol", 0, "specify authentication protocol")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.ClientCert, "clientCert", "", "specify client certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.CACert, "caCert", "", "specify CA certificate")
	f.flagSetAddWifiSettings.StringVar(&ieee8021xCfg.PrivateKey, "privateKey", f.lookupEnvOrString("IEE8021X_PRIVATE_KEY", ""), "specify private key")

	// rpc configure addwifisettings -configstring "{ prop: val, prop2: val }"
	// rpc configure add -config "filename" -secrets "someotherfile"
	if err = f.flagSetAddWifiSettings.Parse(f.commandLineArgs[3:]); err != nil {
		f.printConfigurationUsage()
		return utils.IncorrectCommandLineParameters
	}

	if wifiCfg.ProfileName != "" {
		authMethod := wifi.AuthenticationMethod(wifiCfg.AuthenticationMethod)
		if authMethod == wifi.AuthenticationMethod_WPA_IEEE8021x ||
			authMethod == wifi.AuthenticationMethod_WPA2_IEEE8021x {
			// reuse profilename as configuration reference
			wifiCfg.Ieee8021xProfileName = wifiCfg.ProfileName
			ieee8021xCfg.ProfileName = wifiCfg.ProfileName
		}
	}

	f.LocalConfig.WifiConfigs = append(f.LocalConfig.WifiConfigs, wifiCfg)
	f.LocalConfig.Ieee8021xConfigs = append(f.LocalConfig.Ieee8021xConfigs, ieee8021xCfg)
	err = f.handleLocalConfig()
	if err != nil {
		return utils.FailedReadingConfiguration
	}
	if configJson != "" {
		err := json.Unmarshal([]byte(configJson), &f.LocalConfig)
		if err != nil {
			log.Error(err)
			return utils.IncorrectCommandLineParameters
		}
	}

	if len(f.LocalConfig.WifiConfigs) == 0 {
		log.Error("missing wifi configuration")
		return utils.MissingOrInvalidConfiguration
	}

	if secretsFilePath != "" {
		err = cleanenv.ReadConfig(secretsFilePath, &wifiSecretConfig)
		if err != nil {
			log.Error("error reading secrets file: ", err)
			return utils.FailedReadingConfiguration
		}
	}

	// merge secrets with configs
	err = f.mergeWifiSecrets(wifiSecretConfig)
	if err != nil {
		return err
	}

	// prompt for missing secrets
	err = f.promptForSecrets()
	if err != nil {
		return err
	}
	// verify configs
	err = f.verifyWifiConfigurations()
	if err != nil {
		return err
	}
	return nil
}

func (f *Flags) mergeWifiSecrets(wifiSecretConfig config.SecretConfig) error {
	for _, secret := range wifiSecretConfig.Secrets {
		if secret.ProfileName == "" {
			continue
		}
		if secret.PskPassphrase != "" {
			for i := range f.LocalConfig.WifiConfigs {
				item := &f.LocalConfig.WifiConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PskPassphrase = secret.PskPassphrase
				}
			}
		}
		if secret.Password != "" {
			for i := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.Password = secret.Password
				}
			}
		}
		if secret.PrivateKey != "" {
			for i := range f.LocalConfig.Ieee8021xConfigs {
				item := &f.LocalConfig.Ieee8021xConfigs[i]
				if item.ProfileName == secret.ProfileName {
					item.PrivateKey = secret.PrivateKey
				}
			}
		}
	}
	return nil
}

func (f *Flags) promptForSecrets() error {
	for i := range f.LocalConfig.WifiConfigs {
		item := &f.LocalConfig.WifiConfigs[i]
		if item.ProfileName == "" {
			continue
		}
		authMethod := wifi.AuthenticationMethod(item.AuthenticationMethod)
		if (authMethod == wifi.AuthenticationMethod_WPA_PSK || authMethod == wifi.AuthenticationMethod_WPA2_PSK) &&
			item.PskPassphrase == "" {
			err := f.PromptUserInput("Please enter PskPassphrase for "+item.ProfileName+": ", &item.PskPassphrase)
			if err != nil {
				return err
			}
		}
	}
	for i := range f.LocalConfig.Ieee8021xConfigs {
		item := &f.LocalConfig.Ieee8021xConfigs[i]
		if item.ProfileName == "" {
			continue
		}
		authProtocol := ieee8021x.AuthenticationProtocol(item.AuthenticationProtocol)
		if authProtocol == ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2 && item.Password == "" {
			err := f.PromptUserInput("Please enter password for "+item.ProfileName+": ", &item.Password)
			if err != nil {
				return err
			}
		}
		if authProtocol == ieee8021x.AuthenticationProtocolEAPTLS && item.PrivateKey == "" {
			err := f.PromptUserInput("Please enter private key for "+item.ProfileName+": ", &item.PrivateKey)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *Flags) verifyWifiConfigurations() error {
	priorities := make(map[int]bool)
	for _, cfg := range f.LocalConfig.WifiConfigs {
		//Check profile name is not empty
		if cfg.ProfileName == "" {
			log.Error("missing profile name")
			return utils.MissingOrInvalidConfiguration
		}
		//Check ssid is not empty
		if cfg.SSID == "" {
			log.Error("missing ssid for config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		//Check priority is not empty
		if cfg.Priority <= 0 {
			log.Error("invalid priority for config: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		//Check priority is unique
		if priorities[cfg.Priority] {
			log.Error("priority was specified previously: ", cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
		priorities[cfg.Priority] = true

		authenticationMethod := wifi.AuthenticationMethod(cfg.AuthenticationMethod)
		switch authenticationMethod {
		case wifi.AuthenticationMethod_WPA_PSK:
			fallthrough
		case wifi.AuthenticationMethod_WPA2_PSK:
			if cfg.PskPassphrase == "" {
				log.Error("missing PskPassphrase for config: ", cfg.ProfileName)
				return utils.MissingOrInvalidConfiguration
			}
			break
		case wifi.AuthenticationMethod_WPA_IEEE8021x:
			fallthrough
		case wifi.AuthenticationMethod_WPA2_IEEE8021x:
			if cfg.ProfileName == "" {
				log.Error("missing ieee8021x profile name")
				return utils.MissingOrInvalidConfiguration
			}
			if cfg.PskPassphrase != "" {
				log.Errorf("wifi configuration for 8021x contains passphrase: %s", cfg.ProfileName)
				return utils.MissingOrInvalidConfiguration
			}
			err := f.verifyMatchingIeee8021xConfig(cfg.Ieee8021xProfileName)
			if err != nil {
				return err
			}
			break
		case wifi.AuthenticationMethod_Other:
			log.Errorf("unsupported AuthenticationMethod_Other (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_OpenSystem:
			log.Errorf("unsupported AuthenticationMethod_OpenSystem (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_SharedKey:
			log.Errorf("unsupported AuthenticationMethod_SharedKey (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_DMTFReserved:
			log.Errorf("unsupported AuthenticationMethod_DMTFReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_WPA3_SAE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_SAE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_WPA3_OWE:
			log.Errorf("unsupported AuthenticationMethod_WPA3_OWE (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.AuthenticationMethod_VendorReserved:
			log.Errorf("unsupported AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid AuthenticationMethod_VendorReserved (%d) for config: %s", cfg.AuthenticationMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}

		encryptionMethod := wifi.EncryptionMethod(cfg.EncryptionMethod)
		// NOTE: this is only
		switch encryptionMethod {
		case wifi.EncryptionMethod_TKIP:
			fallthrough
		case wifi.EncryptionMethod_CCMP:
			break
		case wifi.EncryptionMethod_Other:
			log.Errorf("unsupported EncryptionMethod_Other (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_WEP:
			log.Errorf("unsupported EncryptionMethod_WEP (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_None:
			log.Errorf("unsupported EncryptionMethod_None (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		case wifi.EncryptionMethod_DMTFReserved:
			log.Errorf("unsupported EncryptionMethod_DMTFReserved (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		default:
			log.Errorf("invalid EncryptionMethod (%d) for config: %s", cfg.EncryptionMethod, cfg.ProfileName)
			return utils.MissingOrInvalidConfiguration
		}
	}
	return nil
}

func (f *Flags) verifyMatchingIeee8021xConfig(profileName string) error {
	foundOne := false
	for _, ieee802xCfg := range f.LocalConfig.Ieee8021xConfigs {
		if profileName != ieee802xCfg.ProfileName {
			continue
		}
		if foundOne {
			log.Error("duplicate IEEE802x Profile names: ", ieee802xCfg.ProfileName)

			return utils.MissingOrInvalidConfiguration
		}
		foundOne = true
		err := f.verifyIeee8021xConfig(ieee802xCfg)
		if err != nil {
			return utils.MissingOrInvalidConfiguration
		}
	}
	if !foundOne {
		log.Error("missing IEEE802x Profile: ", profileName)
		return utils.MissingOrInvalidConfiguration
	}
	return nil
}

func (f *Flags) verifyIeee8021xConfig(cfg config.Ieee8021xConfig) error {
	var err error = errors.New("Missing or invalid configuration")
	if cfg.Username == "" {
		log.Error("missing username for config: ", cfg.ProfileName)
		return err
	}
	if cfg.CACert == "" {
		log.Error("missing caCert for config: ", cfg.ProfileName)
		return err
	}
	authenticationProtocol := ieee8021x.AuthenticationProtocol(cfg.AuthenticationProtocol)
	// not all defined protocols are supported
	switch authenticationProtocol {
	case ieee8021x.AuthenticationProtocolEAPTLS:
		if cfg.ClientCert == "" {
			log.Error("missing clientCert for config: ", cfg.ProfileName)
			return err
		}
		if cfg.PrivateKey == "" {
			log.Error("missing privateKey for config: ", cfg.ProfileName)
			return err
		}
		break
	case ieee8021x.AuthenticationProtocolPEAPv0_EAPMSCHAPv2:
		if cfg.Password == "" {
			log.Error("missing password for for PEAPv0_EAPMSCHAPv2 config: ", cfg.ProfileName)
			return err
		}
		break
	case ieee8021x.AuthenticationProtocolEAPTTLS_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPTTLS_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolPEAPv1_EAPGTC:
		log.Errorf("unsupported AuthenticationProtocolPEAPv1_EAPGTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_MSCHAPv2:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_MSCHAPv2 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_GTC:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_GTC (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_MD5:
		log.Errorf("unsupported AuthenticationProtocolEAP_MD5 (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_PSK:
		log.Errorf("unsupported AuthenticationProtocolEAP_PSK (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_SIM:
		log.Errorf("unsupported AuthenticationProtocolEAP_SIM (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAP_AKA:
		log.Errorf("unsupported AuthenticationProtocolEAP_AKA (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	case ieee8021x.AuthenticationProtocolEAPFAST_TLS:
		log.Errorf("unsupported AuthenticationProtocolEAPFAST_TLS (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	default:
		log.Errorf("invalid AuthenticationProtocol (%d) for config: %s", cfg.AuthenticationProtocol, cfg.ProfileName)
		return err
	}

	return nil
}
