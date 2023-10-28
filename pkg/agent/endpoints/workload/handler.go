package workload

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/zeebo/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	// to selectors assertion
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager"
	"crypto/ecdsa"
	"encoding/base64"
	"strings"
	"crypto/rand"
	hash256 "crypto/sha256"
	"encoding/pem"

	// "github.com/spiffe/go-spiffe/v2/svid/x509svid"
	mint "github.com/golang-jwt/jwt"
)


type IDClaim struct {
	CN	string		`json:"cn,omitempty"`
	PK	[]byte		`json:"pk,omitempty"`
	LS	*LSVID		`json:"ls,omitempty"`
}

type Payload struct {
	Ver int8		`json:"ver,omitempty"`
	Alg string		`json:"alg,omitempty"`
	Iat	int64		`json:"iat,omitempty"`
	Iss	*IDClaim	`json:"iss,omitempty"`
	Sub	*IDClaim	`json:"sub,omitempty"`
	Aud	*IDClaim	`json:"aud,omitempty"`
}

type LSVID struct {	
	Previous	*LSVID		`json:"previous,omitempty"`
	Payload		*Payload	`json:"payload"`
	Signature	[]byte		`json:"signature"`
}

// type Layer struct {	
// 	// Prev	*LSVID		`json:"prev,omitempty"`
// 	Pla		*Payload
// 	Sig		[]byte
// }

// type LSVID struct {	
// 	Layers	[]Layer
// }

type Manager interface {
	SubscribeToCacheChanges(cache.Selectors) cache.Subscriber
	MatchingIdentities([]*common.Selector) []cache.Identity
	FetchJWTSVID(ctx context.Context, spiffeID spiffeid.ID, audience []string) (*client.JWTSVID, error)
	FetchWorkloadUpdate([]*common.Selector) *cache.WorkloadUpdate
}

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

// Handler implements the Workload API interface
type Config struct {
	Manager                       Manager
	Attestor                      Attestor
	AllowUnauthenticatedVerifiers bool
	AllowedForeignJWTClaims       map[string]struct{}
	TrustDomain                   spiffeid.TrustDomain
	AgentPrivKey				  keymanager.Key
	AgentSVID					  []*x509.Certificate
}

type Handler struct {
	workload.UnsafeSpiffeWorkloadAPIServer
	c Config
}

func New(c Config) *Handler {
	return &Handler{
		c: c,
	}
}

// attest caller and return its LSVID signed by the server
func (h *Handler) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (resp *workload.JWTSVIDResponse, err error) {

	log := rpccontext.Logger(ctx)

	// Retrieve workload identity
	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return nil, err
	}
	identities := h.c.Manager.MatchingIdentities(selectors)

	// Generate LSVID payload using workload identity
	wlPayload, err := h.cert2LSR(identities[0].SVID[0], h.c.AgentSVID[0].URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error converting cert to LSR: %v", err)
	}

	lsvidPayload, err := json.Marshal(wlPayload)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error marshalling payload: %v", err)
	}
	// encode payload
	encodedPayload := base64.RawURLEncoding.EncodeToString(lsvidPayload)

	// Retrieve the workload SPIFFE-ID
	wlSpiffeId, err := spiffeid.FromString(identities[0].Entry.SpiffeId)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch SPIFFE-ID: %v", err)
	}

	// Sign workload LSR using modified FetchJWTSVID endpoint
	svid, err := h.c.Manager.FetchJWTSVID(ctx, wlSpiffeId, []string{encodedPayload})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v", err)
	}
	log.Info("Workload LSVID signed by server	: ", fmt.Sprintf("%s", svid))

	// // Generate Agent LSVID to test embedding it in issuer claim

	// Generate LSR from Agent certificate
	// TODO Create a func to create LSR without using a x509 cert
	agentPayload, err := h.cert2LSR(h.c.AgentSVID[0], h.c.AgentSVID[0].URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error converting cert to LSR: %v", err)
	}

	//  Marshal payload
	agentLSVIDPayload, err := json.Marshal(agentPayload)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error marshalling payload: %v", err)
	}
	// encode payload
	agentEncodedPayload := base64.RawURLEncoding.EncodeToString(agentLSVIDPayload)

	// Retrieve the workload SPIFFE-ID
	agentSpiffeId, err := spiffeid.FromString(h.c.AgentSVID[0].URIs[0].String())
	// spiffeid.New("example.org", h.c.AgentSVID[0].URIs[0].String())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch SPIFFE-ID: %v", err)
	}

	// Sign workload LSR using modified FetchJWTSVID endpoint
	agentLSVID, err := h.c.Manager.FetchJWTSVID(ctx, agentSpiffeId, []string{agentEncodedPayload})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not fetch JWT-SVID: %v", err)
	}

	// decode agent LSVID to LSVID struct
	decAgentLSVID, err := h.DecodeLSVID(agentLSVID.Token)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v", err)
	} 

	// Now, extend LSVID using agent key.
	extendedPayload := &Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&IDClaim{
			CN:	h.c.AgentSVID[0].URIs[0].String(),
			LS:	decAgentLSVID,
		},
		Aud:	&IDClaim{
			CN:	wlSpiffeId.String(),
		},
	}

	// decode svid.token to LSVID struct
	decLSVID, err := h.DecodeLSVID(svid.Token)
	if err != nil {
		log.Fatalf("Error decoding LSVID: %v", err)
	} 

	extLSVID, err := h.ExtendLSVID(decLSVID, extendedPayload, h.c.AgentPrivKey)
	if err != nil {
		log.Fatalf("Error extending LSVID: %v", err)
	} 

	// Format response
	resp = new(workload.JWTSVIDResponse)
	resp.Svids = append(resp.Svids, &workload.JWTSVID{
		SpiffeId: identities[0].Entry.SpiffeId,
		Svid:     extLSVID,
	})

	return resp, nil
}

// FetchJWTBundles processes request for JWT bundles
func (h *Handler) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	// Create the experimental lightweight-SVID for Agent and all bundle
	for i:=0; i< len(h.c.AgentSVID); i++ { 
		// lsvid, err := cert2LSVID(h.c.AgentSVID[0].URIs[0].String(), h.c.AgentSVID[i], h.c.AgentPrivKey, "")
		tmpPayload, err := h.cert2LSR(h.c.AgentSVID[i], h.c.AgentSVID[0].URIs[0].String())
		if err != nil {
			return err
		}

		lsvidPayload, err := json.Marshal(tmpPayload)
		if err != nil {
			return err
		}

		log.Info("SPIFFE-ID		: ", fmt.Sprintf("%s", h.c.AgentSVID[i].URIs[0].String()))
		log.Info("LSVID	Payoad	: ", fmt.Sprintf("%s", &lsvidPayload))
	}
	
	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber := h.c.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if err := sendJWTBundlesResponse(update, stream, log, h.c.AllowUnauthenticatedVerifiers); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// Originally, ValidateJWTSVID processes request for JWT-SVID validation. Modified to prototyping the LSVID validation
// Verify LSVID expiration and signature (TODO)
// input: LSVID 
// for each audience do
// 			verify exp time (TODO)
// 			Set public key 0 as root key
// 			verify all signatures using pk0
// 
// TODO: add support to other algorithms rather than ECDSA
// Maybe should be better an audience that is not an array
func (h *Handler) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {

	log := rpccontext.Logger(ctx)
	if req.Audience == "" {
		log.Error("Missing required audience parameter")
		return nil, status.Error(codes.InvalidArgument, "audience must be specified")
	}

	tmplsvid := strings.Split(req.Audience, ";")

	// set the first public key as LSVID issuer public key
	rootValues := strings.Split(tmplsvid[0], ",")
	rootkey := rootValues[3]

	// validate all LSVIDs using pk0
	for i:=0;i<len(tmplsvid);i++ {
		// log.Info("Validating LSVID	: ", fmt.Sprintf("%v", tmplsvid[i]))
		// log.Info("rootkey	: ", fmt.Sprintf("%v", rootkey))
		_ = ValidateLSVID(ctx, tmplsvid[i], rootkey)
	}
	return &workload.ValidateJWTSVIDResponse{
		// SpiffeId: spiffeID,
		// Claims:   s,
	}, nil
}

func ValidateLSVID(ctx context.Context, lsvid string, key string) bool {

	log := rpccontext.Logger(ctx)
	if lsvid == "" {
		log.Error("Missing required lsvid parameter")
		return false
	}

	tmpAud := strings.Split(lsvid, ";")
	// partPay := strings.Split(lsvid, ",")
	for i:=0;i<len(tmpAud);i++ {
		log.Debug("LSVID: ", tmpAud[i])
		parts := strings.Split(tmpAud[i], ",")
		// fmt.Printf("parts: %v\n\n", parts)

		sig := parts[len(parts)-1]
		log.Debug("Sig: ", sig)

		payload := strings.Join(parts[:len(parts)-1], ",")
		log.Debug("payload: ", payload)

		sigVer := ecdsaVerify2(key, payload, sig)
		log.Debug("sigVerification: ", sigVer)
		if sigVer == false {
			log.Error("Signature validation failed!")
			return false
		}
		log.Info("Signature successfully validated!")
		return true
	}
	return true
}

// ecdsaVerify2 use `ecdsa.VerifyASN1()` to verify signature
func ecdsaVerify2(base64PublicKey string, message string, base64Signature string) bool {
	ecPublicKey, err := loadECPublicKey2(base64PublicKey)
	if err != nil {
		panic(err)
	}

	hash := hash256.Sum256([]byte(message))

	sigBytes, err := base64.RawURLEncoding.DecodeString(base64Signature)
	if err != nil {
		panic(err)
	}

	return ecdsa.VerifyASN1(ecPublicKey, hash[:], sigBytes)
}

func loadECPublicKey2(base64PublicKey string) (*ecdsa.PublicKey, error) {

	fmt.Printf("pubkey: %v\n\n", base64PublicKey)
	publicKeyBytes, err := base64.RawURLEncoding.DecodeString(base64PublicKey)
	if err != nil {
		panic(err)
	}

	pub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errors.New("Failed to parse ECDSA public key")
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("Not a ECDSA public key")
	}
	
	return publicKey, nil
}

// FetchX509SVID processes request for an x509 SVID
func (h *Handler) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	// The agent health check currently exercises the Workload API. Since this
	// can happen with some frequency, it has a tendency to fill up logs with
	// hard-to-filter details if we're not careful (e.g. issue #1537). Only log
	// if it is not the agent itself.
	quietLogging := rpccontext.CallerPID(ctx) == os.Getpid()

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber := h.c.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if err := sendX509SVIDResponse(update, stream, log, quietLogging); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// FetchX509Bundles processes request for x509 bundles
func (h *Handler) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	log := rpccontext.Logger(ctx)

	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		log.WithError(err).Error("Workload attestation failed")
		return err
	}

	subscriber := h.c.Manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			err := sendX509BundlesResponse(update, stream, log, h.c.AllowUnauthenticatedVerifiers)
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func sendX509BundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer, log logrus.FieldLogger, allowUnauthenticatedVerifiers bool) error {
	if !allowUnauthenticatedVerifiers && !update.HasIdentity() {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return status.Error(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeX509BundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X509 bundle response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X509 bundle response")
		return err
	}

	return nil
}

func composeX509BundlesResponse(update *cache.WorkloadUpdate) (*workload.X509BundlesResponse, error) {
	if update.Bundle == nil {
		// This should be purely defensive since the cache should always supply
		// a bundle.
		return nil, errors.New("bundle not available")
	}

	bundles := make(map[string][]byte)
	bundles[update.Bundle.TrustDomainID()] = marshalBundle(update.Bundle.RootCAs())
	if update.HasIdentity() {
		for _, federatedBundle := range update.FederatedBundles {
			bundles[federatedBundle.TrustDomainID()] = marshalBundle(federatedBundle.RootCAs())
		}
	}

	return &workload.X509BundlesResponse{
		Bundles: bundles,
	}, nil
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer, log logrus.FieldLogger, quietLogging bool) (err error) {
	if len(update.Identities) == 0 {
		if !quietLogging {
			log.WithField(telemetry.Registered, false).Error("No identity issued")
		}
		return status.Error(codes.PermissionDenied, "no identity issued")
	}

	log = log.WithField(telemetry.Registered, true)

	resp, err := composeX509SVIDResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	log = log.WithField(telemetry.Count, len(resp.Svids))

	// log and emit telemetry on each SVID
	// a response has already been sent so nothing is
	// blocked on this logic
	if !quietLogging {
		for i, svid := range resp.Svids {
			ttl := time.Until(update.Identities[i].SVID[0].NotAfter)
			log.WithFields(logrus.Fields{
				telemetry.SPIFFEID: svid.SpiffeId,
				telemetry.TTL:      ttl.Seconds(),
			}).Debug("Fetched X.509 SVID")
		}
	}

	return nil
}

func composeX509SVIDResponse(update *cache.WorkloadUpdate) (*workload.X509SVIDResponse, error) {
	resp := new(workload.X509SVIDResponse)
	resp.Svids = []*workload.X509SVID{}
	resp.FederatedBundles = make(map[string][]byte)

	bundle := marshalBundle(update.Bundle.RootCAs())

	for td, federatedBundle := range update.FederatedBundles {
		resp.FederatedBundles[td.IDString()] = marshalBundle(federatedBundle.RootCAs())
	}

	for _, identity := range update.Identities {
		id := identity.Entry.SpiffeId

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &workload.X509SVID{
			SpiffeId:    id,
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			X509SvidKey: keyData,
			Bundle:      bundle,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	return resp, nil
}

func sendJWTBundlesResponse(update *cache.WorkloadUpdate, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer, log logrus.FieldLogger, allowUnauthenticatedVerifiers bool) (err error) {
	if !allowUnauthenticatedVerifiers && !update.HasIdentity() {
		log.WithField(telemetry.Registered, false).Error("No identity issued")
		return status.Error(codes.PermissionDenied, "no identity issued")
	}

	resp, err := composeJWTBundlesResponse(update)
	if err != nil {
		log.WithError(err).Error("Could not serialize JWT bundle response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		log.WithError(err).Error("Failed to send JWT bundle response")
		return err
	}

	return nil
}

func composeJWTBundlesResponse(update *cache.WorkloadUpdate) (*workload.JWTBundlesResponse, error) {
	if update.Bundle == nil {
		// This should be purely defensive since the cache should always supply
		// a bundle.
		return nil, errors.New("bundle not available")
	}

	bundles := make(map[string][]byte)
	jwksBytes, err := bundleutil.Marshal(update.Bundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
	if err != nil {
		return nil, err
	}
	bundles[update.Bundle.TrustDomainID()] = jwksBytes

	if update.HasIdentity() {
		for _, federatedBundle := range update.FederatedBundles {
			jwksBytes, err := bundleutil.Marshal(federatedBundle, bundleutil.NoX509SVIDKeys(), bundleutil.StandardJWKS())
			if err != nil {
				return nil, err
			}
			bundles[federatedBundle.TrustDomainID()] = jwksBytes
		}
	}

	return &workload.JWTBundlesResponse{
		Bundles: bundles,
	}, nil
}

func (h *Handler) getWorkloadBundles(selectors []*common.Selector) (bundles []*bundleutil.Bundle) {
	update := h.c.Manager.FetchWorkloadUpdate(selectors)

	if update.Bundle != nil {
		bundles = append(bundles, update.Bundle)
	}
	for _, federatedBundle := range update.FederatedBundles {
		bundles = append(bundles, federatedBundle)
	}
	return bundles
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}

func keyStoreFromBundles(bundles []*bundleutil.Bundle) jwtsvid.KeyStore {
	trustDomainKeys := make(map[string]map[string]crypto.PublicKey)
	for _, bundle := range bundles {
		trustDomainKeys[bundle.TrustDomainID()] = bundle.JWTSigningKeys()
	}
	return jwtsvid.NewKeyStore(trustDomainKeys)
}

func structFromValues(values map[string]interface{}) (*structpb.Struct, error) {
	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return nil, errs.Wrap(err)
	}

	s := new(structpb.Struct)
	if err := protojson.Unmarshal(valuesJSON, s); err != nil {
		return nil, errs.Wrap(err)
	}

	return s, nil
}

func isClaimAllowed(claim string, allowedClaims map[string]struct{}) bool {
	switch claim {
	case "sub", "exp", "aud":
		return true
	default:
		_, ok := allowedClaims[claim]
		return ok
	}
}


// Helper functions to returnselectors

// generate or extend a new ecdsa signed encoded token
//  receive payload already encoded
func NewECDSAencode(newPayload string, oldToken string, key crypto.Signer) (string, error) {

	// //  Marshal received claimset into JSON
	// cs, _ := json.Marshal(claimset)
	// payload := base64.RawURLEncoding.EncodeToString(cs)

	// If no oldToken, generates a simple assertion
	if oldToken == "" {
		hash 	:= hash256.Sum256([]byte(newPayload))
		s, err 	:= key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err 	!= nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		sig := base64.RawURLEncoding.EncodeToString(s)
		encoded := strings.Join([]string{newPayload, sig}, ".")

		// fmt.Printf("\nUser token size: %d\n", len(payload) + len(sig))

		return encoded, nil
	}
	
	//  Otherwise, append assertion to previous content (oldmain) and sign it
	hash	:= hash256.Sum256([]byte(newPayload + "." + oldToken))
	s, err 	:= ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{newPayload, oldToken, signature}, ".")
	
	// fmt.Printf("\nAssertion size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}

// CertToPEM is a utility function returns a PEM encoded x509 Certificate
func CertToPEM(cert *x509.Certificate) []byte {
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	return pemCert
}

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

func ParseTokenClaims(strAT string) map[string]interface{} {
	// defer timeTrack(time.Now(), "Parse token claims")

		// Parse access token without validating signature
		token, _, err := new(mint.Parser).ParseUnverified(strAT, mint.MapClaims{})
		if err != nil {
			fmt.Printf("Error parsing JWT claims: %v", err)
		}
		claims, _ := token.Claims.(mint.MapClaims)
		
		// fmt.Println(claims)
		return claims
}

func ValidateTokenExp(claims map[string]interface{}) (expresult bool, remainingtime string) {
	// defer timeTrack(time.Now(), "Validate token exp")

	tm := time.Unix(int64(claims["exp"].(float64)), 0)
	remaining := tm.Sub(time.Now())

	if remaining > 0 {
		expresult = true 
	} else {
		expresult = false
	}

	return expresult, remaining.String()

}

// Create an LSVID given a x509 certificate.
// TODO: Update considering the new cert2LSR and LSVID struct
// Format: version.issuer.subject.subjpublickey.expiration.signature
func cert2LSVID(iss string, cert *x509.Certificate, key keymanager.Key, oldmain string) (string, error) {

	// generate encoded public key
	tmppk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	pubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

	// Versioning needs TBD. For poc, considering vr = 1 to ECDSA.
	vr := "1"
	sub := cert.URIs[0].String()
	// Create LSVID payload
	payload :=  "{"+vr+"."+iss[9:]+"."+sub[9:]+"."+fmt.Sprintf("%s", pubkey)+"."+fmt.Sprintf("%v", cert.NotAfter.Unix())+"}"

	// If no oldmain, generates a simple id
	if oldmain == "" {
	
		// hash and sign payload
		hash 	:= hash256.Sum256([]byte(payload))
		s, err 	:= key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err 	!= nil {
			fmt.Printf("Error signing: %s\n", err)
			return "", err
		}
		// Encode signature
		sig := base64.RawURLEncoding.EncodeToString(s)
		// Concatenate payload and signature
		encoded := strings.Join([]string{payload, sig}, ".")

		return encoded, nil
	}
	
	//  Otherwise, append id to previous content and sign it
	hash	:= hash256.Sum256([]byte(payload + "." + oldmain))
	s, err 	:= key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		fmt.Printf("Error signing: %s\n", err)
		return "", err
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	encoded := strings.Join([]string{payload, oldmain, signature}, ".")
	
	fmt.Printf("\nID size: %d\n", len(payload) + len(oldmain)+ len(signature))

	return encoded, nil
}

// Create an LSVID sign request given a x509 certificate.
// Format: version.issuer.subject.subjpublickey.expiration.signature
func (h *Handler) cert2LSR(cert *x509.Certificate, audience string) (*Payload, error) {

	// generate encoded public key
	tmppk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return &Payload{}, err
	}
	// pubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

	// Versioning needs TBD. For poc, considering vr = 1 to ECDSA.
	sub := cert.URIs[0].String()
	// Create LSVID payload
	lsvidPayload := &Payload{
		Ver:	1,
		Alg:	"ES256",
		Iat:	time.Now().Round(0).Unix(),
		Iss:	&IDClaim{
			CN:	h.c.TrustDomain.String(),
		},
		Sub:	&IDClaim{
			CN:	sub,
			PK:	tmppk,
		},
		Aud:	&IDClaim{
			CN:	audience,
		},
	}

	return lsvidPayload, nil
}

func (h *Handler) EncodeLSVID(lsvid *LSVID) (string, error) {
	// Marshal the LSVID struct into JSON
	lsvidJSON, err := json.Marshal(lsvid)
	if err != nil {
		return "", errs.New("error marshaling LSVID to JSON: %v", err)
	}

	// Encode the JSON byte slice to Base64.RawURLEncoded string
	encLSVID := base64.RawURLEncoding.EncodeToString(lsvidJSON)

	return encLSVID, nil
}

func (h *Handler) DecodeLSVID(encLSVID string) (*LSVID, error) {

	fmt.Printf("LSVID to be decoded: %s", encLSVID)
    // Decode the base64.RawURLEncoded LSVID
    decoded, err := base64.RawURLEncoding.DecodeString(encLSVID)
    if err != nil {
        return nil, errs.New("error decoding LSVID: %v", err)
    }

	fmt.Printf("Decoded LSVID to be unmarshaled: %s", decoded)

    // Unmarshal the decoded byte slice into your struct
    var decLSVID LSVID
    err = json.Unmarshal(decoded, &decLSVID)
    if err != nil {
        return nil, errs.New("error unmarshalling LSVID: %v", err)
    }

    return &decLSVID, nil
}

func (h *Handler) ExtendLSVID(lsvid *LSVID, newPayload *Payload, key crypto.Signer) (string, error) {

	// Create the extended LSVID structure
	extLSVID := &LSVID{
		Previous:	lsvid,
		Payload:	newPayload,
	}

	// Marshal to JSON
	// TODO: Check if its necessary to marshal before signing. I mean, we need an byte array, 
	// and using JSON marshaler we got it. But maybe there is a better way?
	tmpToSign, err := json.Marshal(extLSVID)
	if err != nil {
		return "", errs.New("Error generating json: %v", err)
	} 

	// Sign extlSVID
	hash 	:= hash256.Sum256(tmpToSign)
	s, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return "", errs.New("Error generating signed assertion: %v", err)
	} 

	// Set extLSVID signature
	extLSVID.Signature = s

	// Encode signed LSVID
	outLSVID, err := h.EncodeLSVID(extLSVID)
	if err != nil {
		return "", errs.New("Error encoding LSVID: %v", err)
	} 

	return outLSVID, nil

}