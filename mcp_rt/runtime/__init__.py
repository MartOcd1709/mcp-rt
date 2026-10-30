"""Runtime observation (Unit 3): run a server in a sealed network namespace and see whether it sends our test value out.

sandbox.py  stdlib launcher; runs inside the namespace and proves the seal before it execs the server.
observe.py  pure verdict logic: token forms, inspectability, claim and purpose vocabularies, verdict rows.
runner.py   host driver: MCP stdio session, benign arguments, elicitation answers, verdict assembly.
"""
