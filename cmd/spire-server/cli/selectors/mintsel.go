package selectors

import (

	"os"
	"time"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"context"
	"crypto/x509"
    "encoding/pem"
	hash256 "crypto/sha256"
	"crypto"
	"encoding/json"
	"strings"
	"crypto/rand"

	"github.com/mitchellh/cli"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
	

	// To selectors assertion
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/cmd/spire-server/util"

	"github.com/spiffe/spire/pkg/common/pemutil"
	"flag"
	"log"
	"errors"
)

const (
	// Workload API socket path
	socketPath	= "unix:///tmp/spire-agent/public/api.sock"
	
)

var (
	testKey, _ = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`))
)



func NewSelectorAssertionCommand() cli.Command {
	return newSelectorAssertionCommand(common_cli.DefaultEnv)
}

func newSelectorAssertionCommand(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(selectorAssertionCommand))
}

type selectorAssertionCommand struct {
	audience common_cli.CommaStringsFlag
	spiffeID string
	// pid		 int
}

func (c *selectorAssertionCommand) Name() string {
	return "selectors"
}

func (c *selectorAssertionCommand) Synopsis() string {
	return "Mint an assertion containing workload attested selectors"
}

func (c *selectorAssertionCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	if len(c.audience) == 0 {
		return errors.New("audience must be specified")
	}

	// Fetch claims data
	clientSVID 		:= FetchX509SVID()
	clientID 		:= clientSVID.ID.String()
	// clientkey 		:= clientSVID.PrivateKey
	pid 			:= os.Getpid()

	// timestamp
	issue_time 		:= time.Now().Round(0).Unix()

	// uses spiffeid or svid as issuer
	// svidAsIssuer 	:= os.Args[2]

	// generate encoded key
	pubkey 		:= testKey.Public().(*ecdsa.PublicKey)
	encKey, _ 	:= EncodeECDSAPublicKey(pubkey)
	issuer 		:= encKey

	// Retrieve selectors
	selectors, err := ReturnSelectors(pid)
	if err != nil {
		fmt.Println("Error retrieving selectors!")
		os.Exit(1)
	}
	fmt.Printf("Selectors array %s\n", selectors)

	// Define assertion claims
	// kid 			:= base64.RawURLEncoding.EncodeToString([]byte(clientID))
	assertionclaims := map[string]interface{}{
		"iss"		:		issuer,
		"iat"		:	 	issue_time,
		// "kid"		:		kid,
		"sub"		:		clientID,
		"sel"		:		selectors,
	}
	assertion, err := NewECDSAencode(assertionclaims, "", testKey)
	if err != nil {
		fmt.Println("Error generating signed assertion!")
		os.Exit(1)
	} 

	fmt.Println("Generated assertion: ", fmt.Sprintf("%s",assertion))

	return nil
}

// gambi mode on

// Fetch workload X509 SVID
func FetchX509SVID() *x509svid.SVID {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create a `workloadapi.X509Source`, it will connect to Workload API using provided socket.
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		log.Fatalf("Unable to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	return svid
}

// EncodeECDSAPublicKey encodes an *ecdsa.PublicKey to PEM format.
//  TODO: FIX type, that should be different based on input key type
// At this time it only support ECDSA
func EncodeECDSAPublicKey(key *ecdsa.PublicKey) ([]byte, error) {

	derKey, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

	keyBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: derKey,
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// returnSelectors return selectors of a given PID
func ReturnSelectors(pid int) (string, error) {
	logg, _ := test.NewNullLogger()

	// set config parameters
	minimalConfig := func() catalog.Config {
		return catalog.Config{
			Log: logg,
			PluginConfig: catalog.HCLPluginConfigMap{
				"KeyManager": {
					"memory": {},
				},
				"NodeAttestor": {
					"join_token": {},
				},
				"WorkloadAttestor": {
					"docker": {},
					"unix": {},
				},
			},
		}
	}
	config := minimalConfig()

	// retrieve attestators
	repo, _ := catalog.Load(context.Background(), config)
	plugins := repo.GetWorkloadAttestors()

	sChan := make(chan []*common.Selector)
	errChan := make(chan error)

	// Attest
	for _, p := range plugins {
		go func(p workloadattestor.WorkloadAttestor) {
			if selectors, err := p.Attest(context.Background(), pid); err == nil {
				sChan <- selectors
			} else {
				errChan <- err
			}
		}(p)
	}

	// Collect the results
	selectors := []*common.Selector{}
	for i := 0; i < len(plugins); i++ {
		select {
		case s := <-sChan:
			selectors = append(selectors, s...)
		case err := <-errChan:
			log.Fatal("Failed to collect all selectors for PID", err)
		}
	}
	result, err := json.Marshal(selectors)
	if err != nil {
		log.Fatal("Error marshalling selectors", err)
	}

	return fmt.Sprintf("%s", result), nil
}

// generate a new ecdsa signed encoded assertion
func NewECDSAencode(claimset map[string]interface{}, oldmain string, key crypto.Signer) (string, error) {

	//  Marshall received claimset into JSON
	cs, _ := json.Marshal(claimset)
	payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldmain, generates a simple assertion
	if oldmain == "" {
		hash 	:= hash256.Sum256([]byte(payload))
		s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
		if err 	!= nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)
		encoded := strings.Join([]string{payload, sig}, ".")

		fmt.Printf("\nAssertion size: %d\n", len(payload) + len(sig))

		return encoded, nil
	}
	
	//  Otherwise, append assertion to previous content (oldmain) and sign it
	hash	:= hash256.Sum256([]byte(payload + "." + oldmain))
	s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")
	
	fmt.Printf("\nAssertion size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}

func (c *selectorAssertionCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.spiffeID, "spiffeID", "", "SPIFFE ID")
	// fs.DurationVar(&c.ttl, "ttl", 0, "TTL of the JWT-SVID")
	fs.Var(&c.audience, "audience", "Audience claim that will be included in the SVID. Can be used more than once.")
	// fs.StringVar(&c.write, "write", "", "File to write token to instead of stdout")
}