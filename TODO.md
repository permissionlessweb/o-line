
# TODO

<!-- - unify usage of deployment ctx with testnetwork & deploy (standardize design) -->
<!-- - improve sites cli to be gneeric for interacxting with minio-ipfs, utilize sessions design as others -->
<!-- BACKLOGGED -->
<!-- - wire in merkle root db tree to ipfs pinning workflow (this is opt-in feature for validators for x/hash-market) -->
<!-- - pquery trusted/desired providers what they will bid on deployment automate the bid selection process after verified provider will bid -->
<!-- - tensorzero tool function within ergors loop: curate tensorzero tool function loop with error handling and passing back to llm for recursive workflow error identification and tuning.  -->

- single e2e test:
  - extend testnet workflow with terp websites to:
  - deploy local-akash in parallel with local terp
  - deploy static website to local minio-ipfs on akash network
  - bootstrap multiple local ibc chains for ibc testing (terp-core)
  - automate testing html js & wasm-bindgen logic in compiled static websites
    - test passkey was binary use locally via automated scripting and confirmation of use in html website
    - login/logout multiwallet (keplr/metamask)
- query deployments needs full implementation
- improve labeling of deployments
  
- <https://github.com/google/langextract>
- <https://github.com/joshua-mo-143/rig-rlm>
- chaining:  <https://github.com/graniet/rllm/>
- <https://github.com/zircote/rlm-rs>
- spec out background worker processe design
- <https://pypi.org/project/langextract/>
 