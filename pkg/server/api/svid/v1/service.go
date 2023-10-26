package svid

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	// "github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"fmt"
	"encoding/base64"
	"encoding/json"
	"crypto/ecdsa"
)
type IDClaim struct {
	CN	string		`json:"cn,omitempty"`
	PK	string		`json:"pk,omitempty"`
	LS	string		`json:"ls,omitempty"`
}


type LSVID struct {	
	Ver int8		`json:"ver,omitempty"`
	Alg string		`json:"alg,omitempty"`
	Iss	IDClaim		`json:"iss,omitempty"`
	Iat	int64		`json:"iat,omitempty"`
	Sub	IDClaim		`json:"sub,omitempty"`
	Aud	IDClaim		`json:"aud,omitempty"`
}


// RegisterService registers the service on the gRPC server.
func RegisterService(s *grpc.Server, service *Service) {
	svidv1.RegisterSVIDServer(s, service)
}

// Config is the service configuration
type Config struct {
	EntryFetcher api.AuthorizedEntryFetcher
	ServerCA     ca.ServerCA
	TrustDomain  spiffeid.TrustDomain
	DataStore    datastore.DataStore
}

// New creates a new SVID service
func New(config Config) *Service {
	return &Service{
		ca: config.ServerCA,
		ef: config.EntryFetcher,
		td: config.TrustDomain,
		ds: config.DataStore,
	}
}

// Service implements the v1 SVID service
type Service struct {
	svidv1.UnsafeSVIDServer

	ca ca.ServerCA
	ef api.AuthorizedEntryFetcher
	td spiffeid.TrustDomain
	ds datastore.DataStore
}

func (s *Service) MintX509SVID(ctx context.Context, req *svidv1.MintX509SVIDRequest) (*svidv1.MintX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.Csr: api.HashByte(req.Csr),
		telemetry.TTL: req.Ttl,
	})

	if len(req.Csr) == 0 {
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing CSR", nil)
	}

	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "malformed CSR", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "failed to verify CSR signature", err)
	}

	switch {
	case len(csr.URIs) == 0:
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is required", nil)
	case len(csr.URIs) > 1:
		return nil, api.MakeErr(log, codes.InvalidArgument, "only one URI SAN is expected", nil)
	}

	id, err := spiffeid.FromURI(csr.URIs[0])
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is not a valid SPIFFE ID", err)
	}

	if err := api.VerifyTrustDomainWorkloadID(s.td, id); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is invalid", err)
	}

	if err := idutil.CheckIDURLNormalization(csr.URIs[0]); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "CSR URI SAN is malformed", err)
	}

	for _, dnsName := range csr.DNSNames {
		if err := x509util.ValidateDNS(dnsName); err != nil {
			return nil, api.MakeErr(log, codes.InvalidArgument, "CSR DNS name is not valid", err)
		}
	}

	x509SVID, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  id,
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(req.Ttl) * time.Second,
		DNSList:   csr.DNSNames,
		Subject:   csr.Subject,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign X509-SVID", err)
	}
	rpccontext.AuditRPCWithFields(ctx, logrus.Fields{
		telemetry.SPIFFEID:  id.String(),
		telemetry.DNSName:   strings.Join(csr.DNSNames, ","),
		telemetry.Subject:   csr.Subject,
		telemetry.ExpiresAt: x509SVID[0].NotAfter.Unix(),
	})

	return &svidv1.MintX509SVIDResponse{
		Svid: &types.X509SVID{
			Id:        api.ProtoFromID(id),
			CertChain: x509util.RawCertsFromCertificates(x509SVID),
			ExpiresAt: x509SVID[0].NotAfter.Unix(),
		},
	}, nil
}

func (s *Service) MintJWTSVID(ctx context.Context, req *svidv1.MintJWTSVIDRequest) (*svidv1.MintJWTSVIDResponse, error) {

	// log := rpccontext.Logger(ctx)

	var lsvidPayloads []string
	
	// if req.Audience[0] != "" {
	// 	lsvidPayloads = append(lsvidPayloads, req.Audience[0])
	// 	log.Info("appended lsvidPayloads: ", lsvidPayloads)
	// }

	// lsvidPayloads = s.getTrustBundleLSVID(ctx)

	// lsvidPayloads = append(lsvidPayloads, req.Audience[0])


	lsvid, err := s.ca.SignLSVID(ctx, lsvidPayloads)
	if err != nil {
		return nil, err
	}

	return &svidv1.MintJWTSVIDResponse{
		Svid: &types.JWTSVID{
			Token: lsvid,
		},
	}, nil

}

func (s *Service) BatchNewX509SVID(ctx context.Context, req *svidv1.BatchNewX509SVIDRequest) (*svidv1.BatchNewX509SVIDResponse, error) {
	log := rpccontext.Logger(ctx)

	if len(req.Params) == 0 {
		return nil, api.MakeErr(log, codes.InvalidArgument, "missing parameters", nil)
	}

	if err := rpccontext.RateLimit(ctx, len(req.Params)); err != nil {
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to certificate signing rate limiting", err)
	}

	// Fetch authorized entries
	entriesMap, err := s.fetchEntries(ctx, log)
	if err != nil {
		return nil, err
	}

	var results []*svidv1.BatchNewX509SVIDResponse_Result
	for _, svidParam := range req.Params {
		//  Create new SVID
		r := s.newX509SVID(ctx, svidParam, entriesMap)
		results = append(results, r)
		rpccontext.AuditRPCWithTypesStatus(ctx, r.Status, func() logrus.Fields {
			fields := logrus.Fields{
				telemetry.Csr:            api.HashByte(svidParam.Csr),
				telemetry.RegistrationID: svidParam.EntryId,
			}

			if r.Svid != nil {
				fields[telemetry.ExpiresAt] = r.Svid.ExpiresAt
			}

			return fields
		})
	}

	return &svidv1.BatchNewX509SVIDResponse{Results: results}, nil
}

// fetchEntries fetches authorized entries using caller ID from context
func (s *Service) fetchEntries(ctx context.Context, log logrus.FieldLogger) (map[string]*types.Entry, error) {
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, api.MakeErr(log, codes.Internal, "caller ID missing from request context", nil)
	}

	entries, err := s.ef.FetchAuthorizedEntries(ctx, callerID)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch registration entries", err)
	}

	entriesMap := make(map[string]*types.Entry, len(entries))
	for _, entry := range entries {
		entriesMap[entry.Id] = entry
	}

	return entriesMap, nil
}

// newX509SVID creates an X509-SVID using data from registration entry and key from CSR
func (s *Service) newX509SVID(ctx context.Context, param *svidv1.NewX509SVIDParams, entries map[string]*types.Entry) *svidv1.BatchNewX509SVIDResponse_Result {
	log := rpccontext.Logger(ctx)

	switch {
	case param.EntryId == "":
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "missing entry ID", nil),
		}
	case len(param.Csr) == 0:
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "missing CSR", nil),
		}
	}

	log = log.WithField(telemetry.RegistrationID, param.EntryId)

	entry, ok := entries[param.EntryId]
	if !ok {
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.NotFound, "entry not found or not authorized", nil),
		}
	}

	csr, err := x509.ParseCertificateRequest(param.Csr)
	if err != nil {
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "malformed CSR", err),
		}
	}

	if err := csr.CheckSignature(); err != nil {
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.InvalidArgument, "invalid CSR signature", err),
		}
	}

	spiffeID, err := api.TrustDomainMemberIDFromProto(s.td, entry.SpiffeId)
	if err != nil {
		// This shouldn't be the case unless there is invalid data in the datastore
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "entry has malformed SPIFFE ID", err),
		}
	}
	log = log.WithField(telemetry.SPIFFEID, spiffeID.String())

	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  spiffeID,
		PublicKey: csr.PublicKey,
		DNSList:   entry.DnsNames,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		return &svidv1.BatchNewX509SVIDResponse_Result{
			Status: api.MakeStatus(log, codes.Internal, "failed to sign X509-SVID", err),
		}
	}

	return &svidv1.BatchNewX509SVIDResponse_Result{
		Svid: &types.X509SVID{
			Id:        entry.SpiffeId,
			CertChain: x509util.RawCertsFromCertificates(x509Svid),
			ExpiresAt: x509Svid[0].NotAfter.Unix(),
		},
		Status: api.OK(),
	}
}

func (s *Service) NewJWTSVID(ctx context.Context, req *svidv1.NewJWTSVIDRequest) (resp *svidv1.NewJWTSVIDResponse, err error) {
	
	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to JWT signing request rate limiting", err)
	}

	// Add Trust bundle LSVID payload as first LSVID
	// payload := s.getTrustBundleLSVID(ctx)
	payload, err := s.getBundleLSVIDPayload(ctx)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed retrieving bundle LSVID payload", err)
	}

	// Append all received LSVIDs
	payload = append(payload, req.Audience...)

	// Request signature of all LSVID payloads
	lsvid, err := s.ca.SignLSVID(ctx, payload)
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign JWT-SVID", err)
	}

	outLSVID := &types.JWTSVID{
		Token: lsvid,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt:  time.Now().Unix(), 
	}
	// log.Debug("resulting outLSVID: ", outLSVID)

	response := &svidv1.NewJWTSVIDResponse{
		Svid: outLSVID,
	}
	// log.Debug("resulting response: ", response)

	return response, nil
}

func (s *Service) NewDownstreamX509CA(ctx context.Context, req *svidv1.NewDownstreamX509CARequest) (*svidv1.NewDownstreamX509CAResponse, error) {
	log := rpccontext.Logger(ctx)
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.Csr:           api.HashByte(req.Csr),
		telemetry.TrustDomainID: s.td.IDString(),
	})

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		return nil, api.MakeErr(log, status.Code(err), "rejecting request due to downstream CA signing rate limit", err)
	}

	downstreamEntries, isDownstream := rpccontext.CallerDownstreamEntries(ctx)
	if !isDownstream {
		return nil, api.MakeErr(log, codes.Internal, "caller is not a downstream workload", nil)
	}

	entry := downstreamEntries[0]

	csr, err := parseAndCheckCSR(ctx, req.Csr)
	if err != nil {
		return nil, err
	}

	x509CASvid, err := s.ca.SignX509CASVID(ctx, ca.X509CASVIDParams{
		SpiffeID:  s.td.ID(),
		PublicKey: csr.PublicKey,
		TTL:       time.Duration(entry.Ttl) * time.Second,
	})
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to sign downstream X.509 CA", err)
	}

	bundle, err := s.ds.FetchBundle(ctx, s.td.IDString())
	if err != nil {
		return nil, api.MakeErr(log, codes.Internal, "failed to fetch bundle", err)
	}

	if bundle == nil {
		return nil, api.MakeErr(log, codes.NotFound, "bundle not found", nil)
	}

	rawRootCerts := make([][]byte, 0, len(bundle.RootCas))
	for _, cert := range bundle.RootCas {
		rawRootCerts = append(rawRootCerts, cert.DerBytes)
	}
	rpccontext.AuditRPCWithFields(ctx, logrus.Fields{
		telemetry.ExpiresAt: x509CASvid[0].NotAfter.Unix(),
	})

	return &svidv1.NewDownstreamX509CAResponse{
		CaCertChain:     x509util.RawCertsFromCertificates(x509CASvid),
		X509Authorities: rawRootCerts,
	}, nil
}

func (s Service) fieldsFromJWTSvidParams(protoID *types.SPIFFEID, audience []string, ttl int32) logrus.Fields {
	fields := logrus.Fields{
		telemetry.TTL: ttl,
	}
	if protoID != nil {
		// Dont care about parsing error
		id, err := api.TrustDomainWorkloadIDFromProto(s.td, protoID)
		if err == nil {
			fields[telemetry.SPIFFEID] = id.String()
		}
	}

	if len(audience) > 0 {
		fields[telemetry.Audience] = strings.Join(audience, ",")
	}

	return fields
}

func parseAndCheckCSR(ctx context.Context, csrBytes []byte) (*x509.CertificateRequest, error) {
	log := rpccontext.Logger(ctx)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "malformed CSR", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, api.MakeErr(log, codes.InvalidArgument, "invalid CSR signature", err)
	}

	return csr, nil
}

func (s *Service) getTrustBundleLSVID(ctx context.Context) []string {

	log := rpccontext.Logger(ctx)
	bundle, err := s.ds.FetchBundle(ctx, s.td.IDString())
	if err != nil || bundle == nil {
		return nil
	}

	var tbList []string
	for i:=0;i<len(bundle.RootCas);i++ {
		cert, err := x509.ParseCertificate(bundle.RootCas[i].DerBytes)
		if err != nil {
			return nil
		}
		
		tmpLSR, err := s.cert2LSR(ctx, cert)
		if err != nil {
			return nil
		}

		log.Info("Generated trust bundle LSVID payload: ", tmpLSR)
		tbList = append(tbList, tmpLSR)
	}
	return tbList
}

func (s *Service) getBundleLSVIDPayload(ctx context.Context) ([]string, error) {

	log := rpccontext.Logger(ctx)
	tbLSR, err := s.cert2LSR(ctx)
	if err != nil {
		return nil, api.MakeErr(log, status.Code(err), "Error generating LSR", err)
	}
	return []string{tbLSR}, nil
}

// Create an LSVID sign request given a x509 certificate.
// Format: version.issuer.subject.subjpublickey.expiration.signature
func (s *Service) cert2LSR(ctx context.Context, cert ...*x509.Certificate) (string, error) {

	log := rpccontext.Logger(ctx)
	var tmpPayload LSVID
	var jsonData []byte
	var sub  string
	var pub interface{}

	if len(cert) == 0 {
		sub = s.td.IDString()

		// Get the CA pub key using JWTKey
		cakey := s.ca.JWTPubKey()
		if cakey == nil {
			return "", api.MakeErr(log, codes.NotFound, "JWTPubKey not found", nil)
		}
		pub = cakey.(*ecdsa.PublicKey)

		// Get CA pub key using X509CA
		// cakey := s.ca.X509PubKey()
		// if cakey == nil {
		// 	return "", api.MakeErr(log, codes.NotFound, "JWTPubKey not found", nil)
		// }
		// pub = cakey.(*ecdsa.PublicKey)
		
		// generate encoded public key
		tmppk, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", api.MakeErr(log, codes.NotFound, "Error Marshalling Public Key", nil)
		}
		capubkey :=  base64.RawURLEncoding.EncodeToString(tmppk)

		tmpPayload = LSVID{
			Ver:	0,
			Alg:	"ES256",
			Iat:	time.Now().Round(0).Unix(),
			Iss:	IDClaim{
				CN:	s.td.IDString(),
				PK:	capubkey,
			},
			Sub:	IDClaim{
				CN:	s.td.IDString(),
				PK:	capubkey,
			},
		}

		jsonData, err = json.Marshal(tmpPayload)
		if err != nil {
			return "", api.MakeErr(log, codes.NotFound, "Error marshaling data to JSON", nil)
		}

	} else {	 
		// Get the CA pub key using JWTKey
		cakey := s.ca.JWTPubKey()
		if cakey == nil {
			return "", api.MakeErr(log, codes.NotFound, "JWTPubKey not found", nil)
		}
		capub := cakey.(*ecdsa.PublicKey)
		// generate encoded public key
		tmpPKCA, err := x509.MarshalPKIXPublicKey(capub)
		if err != nil {
			return "", api.MakeErr(log, codes.NotFound, "Error Marshalling Public Key", nil)
		}
		capubkey :=  base64.RawURLEncoding.EncodeToString(tmpPKCA)

		sub = cert[0].URIs[0].String()
		pub = cert[0].PublicKey.(*ecdsa.PublicKey)
		// generate encoded public key
		tmpPKSub, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", api.MakeErr(log, codes.NotFound, "Error Marshalling Public Key", nil)
		}
		pubkey :=  base64.RawURLEncoding.EncodeToString(tmpPKSub)

		tmpPayload := LSVID{
			Ver:	1,
			Alg:	"ES256",
			Iat:	time.Now().Round(0).Unix(),
			Iss:	IDClaim{
				CN:	s.td.IDString(),
				PK:	capubkey,
			},
			Sub:	IDClaim{
				CN:	sub,
				PK:	pubkey,
			},
		}

		jsonData, err = json.Marshal(tmpPayload)
		if err != nil {
			return "", api.MakeErr(log, codes.NotFound, "Error marshaling data to JSON", nil)
		}
	}
	
	fmt.Printf("LSVID payload : %s\n", jsonData)
	fmt.Printf("Encoded LSVID payload : %s\n", base64.RawURLEncoding.EncodeToString([]byte(jsonData)))

	return fmt.Sprintf("%s", jsonData), nil
}