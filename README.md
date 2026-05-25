# minimal-secure-protocol

Goal: python implementation of best practice IETF security protocols, for a toy telescope control protocol between a client (astronomy tracking software) and a device (telescope mount) with a few basic operation (read current ra/dec position, slew to new ra/dec position).
But the real goal is to include some setup procedures (configure new device, execute command) and admin interfaces to see how they feel, even if they're just command-line approaches.

Start by scoping out a plan and IETF protocols to handle the common security protections. This might include ACE-OAuth (RFC 9200),  TLS 1.3 (RFC 8446, with BCP 195 / RFC 9325 for usage, perhaps OSCORE (RFC 8613) plus EDHOC (RFC 9528), BRSKI (RFC 8995) , MUD (RFC 8520).

Consider philosophical starting points at  RFC 3365 and RFC 3552 for the doctrine; RFC 7228 for constrained-device vocabulary (so "the ESP32 can't" becomes a measurable claim); RFC 8576, the IAB/IRTF IoT-security survey, as the umbrella; RFC 6973 for privacy.

Background and motivation: Internet protocols like Alpaca for "modern" ASCOM telescope control are lacking most basic security protections. See  https://ascom-standards.org/AlpacaDeveloper/Index.htm for background.
