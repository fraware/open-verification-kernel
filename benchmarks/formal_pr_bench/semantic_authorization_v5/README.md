# Semantic Authorization v5 development cases

This directory exercises contracts derived through more than one source method.

The initial case proves a workspace property in AgentRepository.get, composes
that contract into AgentService.get, and then consumes the composed service
contract from a FastAPI route.

The secure route forwards workspace_id. The regression omits it.

These are public development cases, not protected holdouts.
