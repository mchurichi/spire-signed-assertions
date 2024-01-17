![SPIRE Logo](/doc/images/spire_logo.png)

This is a proof-of-concept version of SPIRE that supports [Lightweight SVID](https://docs.google.com/document/d/15rfAkzNTQa1ycs-fn9hyIYV5HbznPBsxB-f0vxhNJ24). It is part of the HPE-USP-SPIRE project and is used by all samples in [signed-assertions repository](https://github.com/HPE-USP-SPIRE/signed-assertions). It is **not** supposed to be used in production environments without a rigorous code and security review.  

The modifications made to the original SPIRE are:
- The FetchJWTSVID endpoint allows workloads to fetch their LSVID. All other endpoints were kept untouched.  
- The `/opt/spire/conf/agent/agent.conf`
- The environment `script start_spire_env.sh`
