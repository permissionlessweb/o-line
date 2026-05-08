
# TODO
- lockdown minio container network rules:
  - specific public any download
  - specicia authorizations keys for uploading 
  - specific blocking of lan & wan
- unify usage of deployment ctx with testnetwork & deploy (standardize design)
- improve sites cli to be gneeric for interacxting with minio-ipfs, utilize sessions design as others
- tensorzero tool function within ergors loop: curate tensorzero tool function loop with error handling and passing back to llm for recursive workflow error identification and tuning. 
- wire in merkle root db tree to ipfs pinning workflow (this is opt-in feature for validators for x/hash-market)
- unify all config definitions into a standardize workflow.(pre-flight,flight,post-flight). unified definitions and awareness where in workflow variables are defined, useful to minimize tech debt & complexity.
- pquery trusted/desired providers what they will bid on deployment automate the bid selection process after verified provider will bid
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
- generating certificates to send during MsgCreateCertificate needs full implementation
- query deployments needs full implementation
- cancel deployment should also send close deployment msg to deployment
- improve labeling of deployments
- on successful wallet password provision, escape process as workflow has been invoked
- Do not use REST + polling + “is it done?” endpoints, use async jobs + webhook/callbacks + idempotency keys.
- prompt to deploy via sdl -> cancel via (ctrl + c) on password prompt == label of deployment workflow still persist in storage instead of removed.
- do not poll for workflow in cache if its closed (currently still polls for deployments closed on error during inital deplyoment workflow)
- testing it works once deployed: https://github.com/jroddev/wireguard-example
- https://docs.netgate.com/pfsense/en/latest/recipes/wireguard-ra.html
- pihole config
- setup:
  - link templates to .oline home 
  - curate encrypted keys
  - deploy akash-rpc & provider proxy
  <!-- - deploy headscale auth server -->
  - spawn local minio-ipfs node
- SERVER. can we improve how:
  - de/serialization processes (proto/Any type format)
  - the amount of hard-coding is implemented/ can be mitigated (need to minimize as much as possible)
  - how we cache api request for jit/first-come-first serve authentication (to implement support for cw-implementations that require rate-limits/access grant limits to be in serial)
- review cosmwasmvm level integration. can we improve how:
  - we can be more certain that there are no issues to runtime/ atomic/parallel access & state updates?
- review the node networking and communication layer. can we:
  - improve by introducing mempool/block building (each node is its own blockchain, has mempool)
  - make use of ibc protocol for inter-node communication (will work seamlessly with cosmwasmvm layer)
- review the node storage layer. can we improve:
  - how we have implemented network wide state snapshot and compression
  - saving/loading/classifying sessions (comptibilitiy with opencode,goose,claude sessions)
- review the node encryption layer. can we improve:
  - the scatteredness of the encryption impelmentation
  - make use of the custody and keys crates to handle actions in more standardized modular manner (review how penumbra uses actionplans)
- review the configuration layer.
- review the bootstrapping layer.
- review <https://github.com/nearai/ironclaw>, implementation of dynamic tool building, always availablility support, workspace filesystem & hybrid search fusion
- review <https://github.com/jgarzik/brainpro> implementation of agent loops, defining permissions for each agent policy, built in protections, rules, ZDR registry, Resilience Architecture, Persona system, and review how well we would be able to implement these features into our engine
- remove depreceated
- merge cancel and close-deployment into one cmd, so that if we are at any part of a deployment workflwo and we want to cancel we ensure that we send the Msgclose command so that we dont have a deplooyment open or are stale at any point in deployment cycle.
- node flag override (via env variable doesnt persist for entire workflow, shows in depoyment workflow create msg, but not in logs of enginge during automated lifecycle (shows the same defualt provider), caused issues with sequence mismatch after default node lags)
- interactive session should happen in the same window as the cli, not the engine log window
- `provider default qwen-coder --no_key=true` does not display flags correctly (display all flags please). Caused by: code: 'Client specified an invalid argument', message: "API key is required (use no_key=true for keyless providers)"
returniflost@groot e2e-improvements % ergors provider default qwen-coder --no_key=true is the error we wsee
- add model-map -> api-key flag option: give admins an interactive workflow to securely provide api keys given each model-map existing for a provider (they can specify to set api provider as no-api to not inlcude them in iteractive, or if not specified )
- ergors call: flag to sepcify any of the providers registered to call
- llm use: when providers are not set/dedicated for specific functions, we always try to fallback to default providers list, always trying with the local tool as the last choice if none are registered.
- toad support: <https://github.com/batrachianai/toad>
- claw-machine support: <https://github.com/noahsaso/claw-machine>
- configure mpc-like support mimicing: <https://github.com/7836246/claude-team-mcp>
- terrible simplicity, dont know how to use any of the commands, terrible documnentation/example usage in cli commands
- ALL ACTIONS responses should be json formatted for effective parsing with tools and in logs. we do not need fancy formatting for displaying, this will be wired in front ends
- session reference and loading: should be able to name, list , create new sessions, referenced by the location of the project specified (similar to claude code,opencode etc)
- refactor codebase: improve the location of logic, lots of the grpc logic can be isolated and implemented into their respected folders for clear separations of concerns)
- stream logs from deployment
- ssh into deployments
- sg-lang cookbooks
- correctly implement instantiate2 functionality
- email-style addressing (cw-auth@node-ip/dns)
- add flags for permissions to access cosmwasm contracts (mimicing wasmd functionality)
- implement various authenticator middleware contracts (see smart-account implementations)
- implement network topology data and access (alot of TODO's currently)
- ensure api endpionts access/use are standardize thorughout logic (cosmos grpc,api/rpc)
- use label||session id for all cli commands
- ensure all requests made to endpoint are saved in storage layer (middleware handles this, so ensure middleware is sound and correctly implemented)
- display known response from api for helping/debugging when incorrect api defintion is called (generic fallback page/api/cli)
- okapi: <https://github.com/GREsau/okapi/tree/master>

- document ingestion: dedicated vendored & large dependency crates into one singluar file for optimized classification: array of common folder names for these types
- rlm: identify stuck loop and interject (error correction code distribution?)

- prepare plan: ask users questions, log plan to db, prepare specific folders, githubs to fetch to session storage
- execute plan: load files and data into dedicted containers, begin implementation of tasks,

- condense key sharing/rotation,Oauth, threshold signatures into custody and keys libraries
- avoid ERGORS_CUSTODY_PASSWORD usage always, remove from codebase and fix any logic (sentienel) that requires usage of this value
- generating certificates to send during MsgCreateCertificate needs full implementation
- query deployments needs full implementation
- cancel deployment should also send close deployment msg to deployment
- improve labeling of deployments
- on successful wallet password provision, escape process as workflow has been invoked
- Do not use REST + polling + “is it done?” endpoints, use async jobs + webhook/callbacks + idempotency keys.
- prompt to deploy via sdl -> cancel via (ctrl + c) on password prompt == label of deployment workflow still persist in storage instead of removed.
- do not poll for workflow in cache if its closed (currently still polls for deployments closed on error during inital deplyoment workflow)
- basic ssh bootst
- implement connection with network node for bootstrapping
- perform boostrapping functions and report/mitigate/handle results of bootstrapping
- FROST signing
- built in Oauthn for each node
- rlm:
  - <https://github.com/google/langextract>
  - <https://github.com/joshua-mo-143/rig-rlm>
- chaining:  <https://github.com/graniet/rllm/>
- <https://github.com/zircote/rlm-rs>
- spec out background worker processe design
- <https://pypi.org/project/langextract/>
- SERVER. can we improve how:
  - de/serialization processes (proto/Any type format)
  - the amount of hard-coding is implemented/ can be mitigated (need to minimize as much as possible)
  - how we cache api request for jit/first-come-first serve authentication (to implement support for cw-implementations that require rate-limits/access grant limits to be in serial)
- review cosmwasmvm level integration. can we improve how:
  - we can be more certain that there are no issues to runtime/ atomic/parallel access & state updates?
- review the node networking and communication layer. can we:
  - improve by introducing mempool/block building (each node is its own blockchain, has mempool)
  - make use of ibc protocol for inter-node communication (will work seamlessly with cosmwasmvm layer)
- review the node storage layer. can we improve:
  - how we have implemented network wide state snapshot and compression
  - saving/loading/classifying sessions (comptibilitiy with opencode,goose,claude sessions)
- review the node encryption layer. can we improve:
  - the scatteredness of the encryption impelmentation
  - make use of the custody and keys crates to handle actions in more standardized modular manner (review how penumbra uses actionplans)
- review the configuration layer.
- review the bootstrapping layer.
- review <https://github.com/nearai/ironclaw>, implementation of dynamic tool building, always availablility support, workspace filesystem & hybrid search fusion
- review <https://github.com/jgarzik/brainpro> implementation of agent loops, defining permissions for each agent policy, built in protections, rules, ZDR registry, Resilience Architecture, Persona system, and review how well we would be able to implement these features into our engine
- remove depreceated
- use specific python rlm design // hooks
- ergo-rs cli hooks:
- integrate code coverage report: need to reach > 90%
- simplify/unify akash network testing infra. delete old dev-network setup , utilize ict-rs for full workflow
- update dns cli to mirror cli for api design. need the following api support:
  - dns text records
  - tunnel api
- toad support: <https://github.com/batrachianai/toad>
- claw-machine support: <https://github.com/noahsaso/claw-machine>
  - configure mpc-like support mimicing: <https://github.com/7836246/claude-team-mcp>
- ergors call: flag to sepcify any of the providers registered to call
- llm use: when providers are not set/dedicated for specific functions, we always try to fallback to default providers list, always trying with the local tool as the last choice if none are registered.
- add model-map -> api-key flag option: give admins an interactive workflow to securely provide api keys given each model-map existing for a provider (they can specify to set api provider as no-api to not inlcude them in iteractive, or if not specified )
- merge cancel and close-deployment into one cmd, so that if we are at any part of a deployment workflow and we want to cancel we ensure that we send the Msgclose command so that we dont have a deplooyment open or are stale at any point in deployment cycle.
- node flag override (via env variable doesnt persist for entire workflow, shows in depoyment workflow create msg, but not in logs of enginge during automated lifecycle (shows the same defualt provider), caused issues with sequence mismatch after default node lags)
- interactive session should happen in the same window as the cli, not the engine log window
- `provider default qwen-coder --no_key=true` does not display flags correctly (display all flags please). Caused by: code: 'Client specified an invalid argument', message: "API key is required (use no_key=true for keyless providers)"
returniflost@groot e2e-improvements % ergors provider default qwen-coder --no_key=true is the error we wsee
- terrible simplicity, dont know how to use any of the commands, terrible documnentation/example usage in cli commands
- ALL ACTIONS responses should be json formatted for effective parsing with tools and in logs. we do not need fancy formatting for displaying, this will be wired in front ends
- session reference and loading: should be able to name, list , create new sessions, referenced by the location of the project specified (similar to claude code,opencode etc)
- refactor codebase: improve the location of logic, lots of the grpc logic can be isolated and implemented into their respected folders for clear separations of concerns)
- stream logs from deployment
- ssh into deployments
- sg-lang cookbooks
- use specific python rlm design // hooks
- correctly implement instantiate2 functionality
- email-style addressing (cw-auth@node-ip/dns)
- add flags for permissions to access cosmwasm contracts (mimicing wasmd functionality)
- implement various authenticator middleware contracts (see smart-account implementations)
- implement network topology data and access (alot of TODO's currently)
- ensure api endpionts access/use are standardize thorughout logic (cosmos grpc,api/rpc)
- use label||session id for all cli commands
- ensure all requests made to endpoint are saved in storage layer (middleware handles this, so ensure middleware is sound and correctly implemented)
- display known response from api for helping/debugging when incorrect api defintion is called (generic fallback page/api/cli)
- okapi: <https://github.com/GREsau/okapi/tree/master>
- document ingestion: dedicated vendored & large dependency crates into one singluar file for optimized classification: array of common folder names for these types
- rlm: identify stuck loop and interject (error correction code distribution?)
- prepare plan: ask users questions, log plan to db, prepare specific folders, githubs to fetch to session storage
- execute plan: load files and data into dedicted containers, begin implementation of tasks,
- condense key sharing/rotation,Oauth, threshold signatures into custody and keys libraries
- avoid ERGORS_CUSTODY_PASSWORD usage always, remove from codebase and fix any logic (sentienel) that requires usage of this value
- define modular decoding scripts for fractal topography metadata ingestion
- ensure storage compression maps associations between the recursive agentic task tree deterministically
- spec out spawining/bootstrapping clones of images, with custom configurations, key generations
- Python REPL:
  - <https://github.com/shobrook/suss>: diff code reviews
  - <https://github.com/shobrook/weightgain>: improve embeddings
- define scripts with instructions to run for each step in agentic orchestration
- prompt populating logic: prompt templates for specific actions filled in with session/agentic specific data (git worktree commands, agents/subagents to spawn)
- <https://models.dev/>
- basic ssh bootst
- implement connection with network node for bootstrapping
- perform boostrapping functions and report/mitigate/handle results of bootstrapping
- FROST signing
- built in Oauthn for each node
- rlm:
  - <https://github.com/google/langextract>
  - <https://github.com/joshua-mo-143/rig-rlm>
- chaining:  <https://github.com/graniet/rllm/>
- <https://github.com/zircote/rlm-rs>
- spec out background worker processe design
- ergo-rs cli hooks:
- <https://pypi.org/project/langextract/>
wireguard e2e test:replace specific heuristic logic with benchmarking usage of tools heuristic code isbeing replaced for. this is common crates that have unit test and we can implement uutils test taht are generating test data we can then scale an duse for high quality sft on the usage of the engine via the describpteve rlm workflow in contrast to the logic. this idea came from removing the git2 repo crate, since we expect models wto have their weights with github capabiliities, so this can be a nice way to maximize enrgy and reuse the test-macro fr rlm property test data curation .
We can update how we keep track of the following values to a dedicated layer in the storage tree. This will allow us to have public and private commitments to node configurations & storage paramters.
 `NetworkTopology`
 `NodeConfig`
 `AgentCapabilities`### CONFIG

## Minio + IPFS
## ASAP
## DNS ASAP
## TESTING ASAP
## VARIABLE/CONFIG ASAPat TODO.md
# PRIORITIZE SOVEREIGN MODEL USE
## OPTIMIZATIONS
### COMMAND IMPROVEMENTS#### `ergors deploy register-providers`#### `ergors deploy`#### `ergors ask rml query`## COSMWASM## NETWORK## NODE ACTIONS
## SECURITY
## COMMUNICATION## DEPLOYMENTS### STORAGE LAYER ARCHITECTURE
## ORCHESTRATOR SERVICE
### BOOTSTRAPPING
## Secret Values
## TESTING## AI### AI TOOLS
### RLM
## AGENT WORKSPACES
## Research
## RLM## REVIEWS
## OPTIMIZATIONS
### COMMAND IMPROVEMENTS
#### `ergors deploy register-providers`
#### `ergors ask rml query`
## COSMWASM
## NETWORK
## NODE ACTIONS
## SECURITY
## COMMUNICATION
## DEPLOYMENTS
## AI
### AI TOOLS
### RLM
## AGENT WORKSPACES
### OPENAI,CLAUDE,GROK,KIMI TOOLS
## TEXTUALIZE
## Research
## RLM
## REVIEWS

https://github.com/opencontainers/runc# PRIORITIZE SOVEREIGN MODEL USE
**Issues**: [#6 Key Management & Auth](https://github.com/permissionlessweb/ergors/issues/6)
**Issues**: [#11 Agentic Workflow Enhancements](https://github.com/permissionlessweb/ergors/issues/11) | [#8 Testing Infrastructure](https://github.com/permissionlessweb/ergors/issues/8)
**Issues**: [#3 Storage & State Architecture](https://github.com/permissionlessweb/ergors/issues/3)
**Issues**: [#16 1-Click Deployment System](https://github.com/permissionlessweb/ergors/issues/16) | [#1 Akash Deployment](https://github.com/permissionlessweb/ergors/issues/1)
**Issues**: [#4 Network Identity & Consensus](https://github.com/permissionlessweb/ergors/issues/4)
**Issues**: [#2 CosmWasm Integration](https://github.com/permissionlessweb/ergors/issues/2)
**Issues**: [#7 Privacy Primitives](https://github.com/permissionlessweb/ergors/issues/7) | [#13 Embedding & RAG](https://github.com/permissionlessweb/ergors/issues/13) | [#3 Storage Architecture](https://github.com/permissionlessweb/ergors/issues/3) | [#14 Cosmos Query Macro](https://github.com/permissionlessweb/ergors/issues/14) | [#1 Akash Deployment](https://github.com/permissionlessweb/ergors/issues/1)
**Issues**: [#6 Key Management & Auth](https://github.com/permissionlessweb/ergors/issues/6)
**Issues**: [#9 Observability Stack](https://github.com/permissionlessweb/ergors/issues/9) | [#15 LLM Router Improvements](https://github.com/permissionlessweb/ergors/issues/15)
**Issues**: [#5 Configuration System Hardening](https://github.com/permissionlessweb/ergors/issues/5)
**Issues**: [#8 Testing Infrastructure](https://github.com/permissionlessweb/ergors/issues/8)
**Issues**: [#11 Agentic Workflow Enhancements](https://github.com/permissionlessweb/ergors/issues/11) | [#12 Tool Integrations](https://github.com/permissionlessweb/ergors/issues/12) | [#10 Benchmarking & Optimization](https://github.com/permissionlessweb/ergors/issues/10) | [#17 UI & Visualization](https://github.com/permissionlessweb/ergors/issues/17)
**Issues**: [#12 Tool Integrations](https://github.com/permissionlessweb/ergors/issues/12)
**Issues**: [#11 Agentic Workflow Enhancements](https://github.com/permissionlessweb/ergors/issues/11)### OPENAI,CLAUDE,GROK,KIMI TOOLS
**Issues**: [#17 UI & Visualization](https://github.com/permissionlessweb/ergors/issues/17)
**Issues**: [#13 Embedding & RAG](https://github.com/permissionlessweb/ergors/issues/13)
**Issues**: [#12 Tool Integrations](https://github.com/permissionlessweb/ergors/issues/12)## TEXTUALIZE
