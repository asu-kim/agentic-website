# agentic-website

This repository provides the website implementation accompanying our case study on **fine-grained access control for agentic AI in critical tasks**, where autonomous agents act on behalf of a human user under constrained, verifiable permissions.

# Directory structure
---
- **agent**: Contains agent-side experiment scripts for delegated access workflows. The `log/` subdirectory stores execution logs including latency measurement.
- **iotauth**: Includes the [Secure Swarm Toolkit (SST)](https://github.com/iotauth/iotauth/tree/master) Auth component as a Git submodule.  
  This serves as the **Key Distribution Service (KDS)** responsible for:
  - generating session keys for delegated access
  - validating ownership through ExpectedOwnerGroups
  - enforcing trust-level–dependent validity periods
- **website**: Directory for an access-controlled website.  
  The system is composed of:
  - a **React front-end** (JavaScript) used by both human users and agents,
  - a **Python Flask back-end** that enforces delegated access control, performs HMAC verification, and interfaces with Auth,
  - and routes for login, HMAC authentication, and scoped data retrieval.

Detailed instructions for running the website and reproducing our experiments can be found in  **[`website/README.md`](https://github.com/asu-kim/agentic-website/tree/main/website/README.md)**.

# Contributors
---
- [Sunyoung Kim](https://github.com/sunnykim638)
- [Hokeun Kim](https://hokeun.github.io/)

# Disclaimer
---
This software is a research prototype intended for academic evaluation.
This repository includes modified source code of an open-source library. Users must use the provided source codes with caution at their own risk.
