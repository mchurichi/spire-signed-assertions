![SPIRE Logo](/doc/images/spire_logo.png)

SPIRE is hosted by the [Cloud Native Computing Foundation](https://cncf.io) (CNCF)  [as an incubation-level project](https://www.cncf.io/blog/2020/06/22/toc-approves-spiffe-and-spire-to-incubation/). If you are an organization that wants to help shape the evolution of technologies that are container-packaged, dynamically-scheduled and microservices-oriented, consider joining the CNCF.

## Important

This is a proof-of-concept version of SPIRE that includes support to [Lightweight SVID](https://docs.google.com/document/d/15rfAkzNTQa1ycs-fn9hyIYV5HbznPBsxB-f0vxhNJ24).  
It modify the FetchJWTSVID endpoint to allow workloads fetch their LSVID. All other endpoints was kept original.  
It is part of HPE-USP-SPIRE project and used by all samples in [signed-assertions repository](https://github.com/HPE-USP-SPIRE/signed-assertions).  
It is **not** supposed to be used in production environments without a rigorous code and security review.  
