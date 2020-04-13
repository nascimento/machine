package provision

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/docker/machine/libmachine/auth"
	"github.com/docker/machine/libmachine/cert"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/engine"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/provision/pkgaction"
	"github.com/docker/machine/libmachine/provision/serviceaction"
	"github.com/docker/machine/libmachine/swarm"
)

func init() {
	Register("WindowsContainer", &RegisteredProvisioner{
		New: NewWindowsContainerProvisioner,
	})
}

func NewWindowsContainerProvisioner(d drivers.Driver) Provisioner {
	return &WindowsContainerProvisioner{
		GenericProvisioner{
			SSHCommander:      GenericSSHCommander{Driver: d},
			DockerOptionsDir:  "C:/ProgramData/docker/certs.d",
			DaemonOptionsFile: "C:/ProgramData/docker/config/daemon.json",
			OsReleaseID:       "windowscontainer",
			Packages:          []string{},
			Driver:            d,
		},
	}
}

type WindowsContainerProvisioner struct {
	GenericProvisioner
}

func (provisioner *WindowsContainerProvisioner) String() string {
	return "windowscontainer"
}

func (provisioner *WindowsContainerProvisioner) Package(name string, action pkgaction.PackageAction) error {
	return nil
}

func (provisioner *WindowsContainerProvisioner) Provision(swarmOptions swarm.Options, authOptions auth.Options, engineOptions engine.Options) error {
	provisioner.SwarmOptions = swarmOptions
	provisioner.AuthOptions = authOptions
	provisioner.EngineOptions = engineOptions
	swarmOptions.Env = engineOptions.Env

	storageDriver, err := decideStorageDriver(provisioner, "overlay2", engineOptions.StorageDriver)
	if err != nil {
		return err
	}

	provisioner.EngineOptions.StorageDriver = storageDriver

	dockerDir := provisioner.GetDockerOptionsDir()
	if _, err := provisioner.SSHCommand(fmt.Sprintf("mkdir -p %s -Force", dockerDir)); err != nil {
		return err
	}

	provisioner.AuthOptions = setRemoteAuthOptions(provisioner)

	// if err := WindowsConfigureAuth(provisioner, swarmOptions, authOptions, engineOptions); err != nil {
	// 	return err
	// }

	// CONFIGURATION
	driver := provisioner.GetDriver()
	machineName := driver.GetMachineName()
	getAuthOptions := provisioner.GetAuthOptions()
	getSwarmOptions := provisioner.GetSwarmOptions()
	org := mcnutils.GetUsername() + "." + machineName
	bits := 2048

	ip, err := driver.GetIP()
	if err != nil {
		return err
	}

	log.Info("Copying certs to the local machine directory...")

	log.Info(filepath.Join(getAuthOptions.StorePath, "ca.pem"))
	if err := mcnutils.CopyFile(getAuthOptions.CaCertPath, filepath.Join(getAuthOptions.StorePath, "ca.pem")); err != nil {
		return fmt.Errorf("Copying ca.pem to machine dir failed: %s", err)
	}

	if err := mcnutils.CopyFile(getAuthOptions.ClientCertPath, filepath.Join(getAuthOptions.StorePath, "cert.pem")); err != nil {
		return fmt.Errorf("Copying cert.pem to machine dir failed: %s", err)
	}

	if err := mcnutils.CopyFile(getAuthOptions.ClientKeyPath, filepath.Join(getAuthOptions.StorePath, "key.pem")); err != nil {
		return fmt.Errorf("Copying key.pem to machine dir failed: %s", err)
	}

	// The Host IP is always added to the certificate's SANs list
	hosts := append(getAuthOptions.ServerCertSANs, ip, "localhost")
	log.Debugf("generating server cert: %s ca-key=%s private-key=%s org=%s san=%s",
		getAuthOptions.ServerCertPath,
		getAuthOptions.CaCertPath,
		getAuthOptions.CaPrivateKeyPath,
		org,
		hosts,
	)

	// TODO: Switch to passing just authOptions to this func
	// instead of all these individual fields
	err = cert.GenerateCert(&cert.Options{
		Hosts:       hosts,
		CertFile:    getAuthOptions.ServerCertPath,
		KeyFile:     getAuthOptions.ServerKeyPath,
		CAFile:      getAuthOptions.CaCertPath,
		CAKeyFile:   getAuthOptions.CaPrivateKeyPath,
		Org:         org,
		Bits:        bits,
		SwarmMaster: getSwarmOptions.Master,
	})

	if err != nil {
		return fmt.Errorf("error generating server cert: %s", err)
	}

	if err := provisioner.Service("docker", serviceaction.Stop); err != nil {
		return err
	}

	// if _, err := provisioner.SSHCommand(`if [ ! -z "$(ip link show docker0)" ]; then sudo docker; fi`); err != nil {
	// 	return err
	// }

	// upload certs and configure TLS auth
	caCert, err := ioutil.ReadFile(getAuthOptions.CaCertPath)
	if err != nil {
		return err
	}

	serverCert, err := ioutil.ReadFile(getAuthOptions.ServerCertPath)
	if err != nil {
		return err
	}
	serverKey, err := ioutil.ReadFile(getAuthOptions.ServerKeyPath)
	if err != nil {
		return err
	}

	log.Info("Copying certs to the remote machine...")

	// printf will choke if we don't pass a format string because of the
	// dashes, so that's the reason for the '%%s'
	certTransferCmdFmt := "New-Item %s; Set-Content %s '%s'"

	// These ones are for Jessie and Mike <3 <3 <3
	if _, err := provisioner.SSHCommand(fmt.Sprintf(certTransferCmdFmt, getAuthOptions.CaCertRemotePath, getAuthOptions.CaCertRemotePath, string(caCert))); err != nil {
		return err
	}

	if _, err := provisioner.SSHCommand(fmt.Sprintf(certTransferCmdFmt, getAuthOptions.ServerCertRemotePath, getAuthOptions.ServerCertRemotePath, string(serverCert))); err != nil {
		return err
	}

	if _, err := provisioner.SSHCommand(fmt.Sprintf(certTransferCmdFmt, getAuthOptions.ServerKeyRemotePath, getAuthOptions.ServerKeyRemotePath, string(serverKey))); err != nil {
		return err
	}

	dockerURL, err := driver.GetURL()
	if err != nil {
		return err
	}
	u, err := url.Parse(dockerURL)
	if err != nil {
		return err
	}
	dockerPort := engine.DefaultPort
	parts := strings.Split(u.Host, ":")
	if len(parts) == 2 {
		dPort, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}
		dockerPort = dPort
	}

	// DOCKER CONFIG
	log.Info("Generating daemon.json configuration file")

	var (
		engineCfg bytes.Buffer
	)

	driverNameLabel := fmt.Sprintf("provider=%s", driver.DriverName())
	provisioner.EngineOptions.Labels = append(provisioner.EngineOptions.Labels, driverNameLabel)

	engineConfigTmpl := `
{
  \"hosts\": [\"tcp://0.0.0.0:{{.DockerPort}}\", \"npipe://\"],
	\"tlsverify\": true,
	\"tls\": true,
	\"experimental\": true,
	\"tlscacert\": \"{{.AuthOptions.CaCertRemotePath}}\",
	\"tlscert\": \"{{.AuthOptions.ServerCertRemotePath}}\",
	\"tlskey\": \"{{.AuthOptions.ServerKeyRemotePath}}\",
	\"labels\": [{{ range .EngineOptions.Labels }}\"{{.}}\"{{ end }}],
	\"insecure-registries\": [{{ range .EngineOptions.InsecureRegistry }}\"{{.}}\"{{ end }}],
	\"registry-mirrors\": [{{ range .EngineOptions.RegistryMirror }}\"{{.}}\"{{ end }}]
}
`
	t, err := template.New("engineConfig").Parse(engineConfigTmpl)
	if err != nil {
		return err
	}

	engineConfigContext := EngineConfigContext{
		DockerPort:    dockerPort,
		AuthOptions:   provisioner.AuthOptions,
		EngineOptions: provisioner.EngineOptions,
	}

	t.Execute(&engineCfg, engineConfigContext)

	dkrcfg := &DockerOptions{
		EngineOptions:     engineCfg.String(),
		EngineOptionsPath: provisioner.DaemonOptionsFile,
	}
	// DOCKER CONFIG

	log.Info("Setting Docker configuration on the remote daemon...")

	if _, err = provisioner.SSHCommand(fmt.Sprintf("mkdir -p %s -Force; Set-Content %s '%s'", path.Dir(dkrcfg.EngineOptionsPath), dkrcfg.EngineOptionsPath, string(dkrcfg.EngineOptions))); err != nil {
		return err
	}

	if err := provisioner.Service("docker", serviceaction.Start); err != nil {
		return err
	}

	// return WaitForDocker(p, dockerPort)
	// CONFIGURATION

	return nil

	// err = configureSwarm(provisioner, swarmOptions, provisioner.AuthOptions)
	// return err
}

func (provisioner *WindowsContainerProvisioner) Service(name string, action serviceaction.ServiceAction) error {
	command := fmt.Sprintf("%s-Service %s", action.String(), name)

	if _, err := provisioner.SSHCommand(command); err != nil {
		return err
	}

	return nil
}

func (provisioner *WindowsContainerProvisioner) dockerDaemonResponding() bool {
	log.Debug("checking docker daemon")

	if out, err := provisioner.SSHCommand("docker version"); err != nil {
		log.Warnf("Error getting SSH command to check if the daemon is up: %s", err)
		log.Debugf("'docker version' output:\n%s", out)
		return false
	}

	// The daemon is up if the command worked.  Carry on.
	return true
}
