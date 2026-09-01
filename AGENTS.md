# Repository Instructions

- Keep this repository independent from the Mirai TypeScript implementation.
- Shared public schemas and corpus files may be read from a Mirai checkout;
  TypeScript runtime modules and CLI results must not be imported as checker
  logic.
- Do not execute external effects or treat conformance evidence as runtime
  authorization.
- Require Python 3.12 or newer and run `python -m unittest discover -s tests -v`
  before a release.
- Never commit credentials, private runtime traces or generated virtual
  environments.
