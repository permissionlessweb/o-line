
# TODO

- pquery trusted/desired providers what they will bid on deployment automate the bid selection process after verified provider will bid
- tensorzero tool function within ergors loop
- wire in merkle root db tree to ipfs pinning workflow (this is opt-in feature for validators for x/hash-market)
- rmcp-openapi-server: generate our own workflows via :  https://pfrest.org/SWAGGER_AND_OPENAPI/#openapi-schema https://github.com/pfrest/pfSense-pkg-RESTAPI
 https://gitlab.com/lx-industries/rmcp-openapi
- single e2e test:
  - extend testnet workflow with terp websites to:
  - deploy local-akash in parallel with local terp
  - deploy static website to local minio-ipfs on akash network
  - bootstrap multiple local ibc chains for ibc testing (terp-core)
  - automate testing html js & wasm-bindgen logic in compiled static websites
    - test passkey was binary use locally via automated scripting and confirmation of use in html website
    - login/logout multiwallet (keplr/metamask)
  - wire in headstash deployment use for testnet deployment & headstahsh static mint page (generat zk-proofs from wallet connections and wasm-bindgen (local testnet )


wireguard e2e test:

- testing it works once deployed: https://github.com/jroddev/wireguard-example
- https://docs.netgate.com/pfsense/en/latest/recipes/wireguard-ra.html
-