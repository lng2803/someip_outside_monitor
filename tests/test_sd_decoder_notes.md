# Manual smoke-test checklist

1. Start the GUI and click **Start agent listener**.
2. Start the agent on the SBC with the reachable PC IP.
3. Click **Start capture**.
4. Generate SOME/IP traffic from a second SBC or a SOME/IP test application.
5. Confirm packet rows arrive at the GUI.
6. Send an SD OfferService packet and verify the service table/event log.
7. Click **Stop capture**, then **Start capture**.
8. Test an invalid filter; verify that the agent reports an error rather than crashing.

For repeatable protocol tests, create PCAP fixtures with known SOME/IP-SD messages and add automated parser unit tests before relying on the service table.
