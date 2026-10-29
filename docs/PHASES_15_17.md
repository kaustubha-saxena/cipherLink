# CipherLink traffic and integrity experiments

## Phase 15: traffic dashboard

Capture traffic with Wireshark/TShark and generate a dashboard report:

```powershell
python traffic-analysis/capture.py --list-interfaces
python traffic-analysis/capture.py --interface "Wi-Fi" --duration 60 --filter "tcp port 443" --output traffic-analysis/phase16-cipherlink.pcapng
python traffic-analysis/analyzer.py traffic-analysis/phase16-cipherlink.pcapng --csv traffic-analysis/phase16-cipherlink-packets.csv --xml traffic-analysis/phase16-cipherlink.xml
```

Replace `Wi-Fi` with the interface name printed by the first command. If the capture is restricted to a known backend address, use a capture filter such as `host <backend-ip> and tcp port 443`. DNS addresses can change, so resolve the backend address immediately before capturing. Open `/traffic-analysis` and load the generated `.analysis.json` report and packet CSV. The analyzer can also write XML directly with `--xml`; the dashboard's **Export as XML** button posts the loaded, already parsed report and packet CSV rows to the backend endpoint without re-reading the PCAP.

The dashboard reports packet count, captured bytes, average frame size, TCP ACK round-trip samples, throughput, retransmissions, packet counts over time, packet-size distribution, protocol distribution, throughput over time, and TCP ACK RTT against the size of the acknowledged payload. It also plots text message size against end-to-end delivery acknowledgment RTT from messages sent by this browser. The latter measures until the partner verifies/decrypts and acknowledges the message; its samples are stored in the sender's browser. Wireshark's ACK RTT is a transport-level estimate; payload length is a TCP segment measurement, not a reconstructed WebSocket message size. Missing RTT samples remain `N/A` rather than being estimated or fabricated.

The checked-in `cipherlink-test.pcapng` is a real capture from the host, but it includes unrelated background network traffic. Its regenerated report has 2,582 packets, 409 TLS packets, 434 TCP ACK RTT samples, and 23 retransmissions. Use a fresh filtered capture for a clean experiment and keep IP-address metadata private.

## Phase 16: packet-sniffing experiment

1. Use the hosted CipherLink page on Device A and Device B. Confirm both are using the hosted HTTPS page so the chat WebSocket uses WSS.
2. Start Wireshark on the active network interface before sending a message. Use the capture filter `tcp port 443`; narrow it to the backend IP if you have resolved that address.
3. Create and join a room, then send the exact marker `Confidential message from Device A` from A to B. Confirm B sees the message.
4. Stop the capture and save it as `traffic-analysis/phase16-cipherlink.pcapng`.
5. In Wireshark, filter on `tls` and inspect the connection's TLS Application Data. Search packet bytes for the exact marker with the display filter `frame contains "Confidential message from Device A"`; it should return no matching frame. The TLS packets still reveal endpoint, timing, and size metadata.
6. Run the Phase 15 analyzer command on that capture and load its `.analysis.json` output in `/traffic-analysis`.

The existing checked-in capture demonstrates TLS traffic from the host, but it is not a controlled capture of the marker above. Record the fresh capture and Wireshark result when presenting this experiment.

## Phase 17: tampering experiment

1. Join the same room from Device A and Device B and wait for `End-to-end encrypted`.
2. On A, expand **PHASE 17 · TAMPERING EXPERIMENT**, enter a message, and click **Encrypt**. The box displays the plaintext, ciphertext, nonce, and AES-GCM tag.
3. Click **Simulate Tampering** to flip one ciphertext byte while retaining the tag.
4. Click **Decrypt** on A. The result should show red `AUTHENTICATION FAILED`, no plaintext, and `PASS — tampered ciphertext rejected`.
5. Click **Send Tampered Message to Device B**. The sender signs the altered envelope so B can pass the message-signature check and exercise AES-GCM authentication.
6. B should reject decryption, show an integrity-failure event, and send `INTEGRITY_FAILURE` to the backend. A's Phase 17 box reports Device B's rejection; the room activity log should show `MESSAGE_SENT` and `INTEGRITY_FAILURE` while the audit chain remains verified.
7. On A, click **Reset**, then **Decrypt**. The untouched ciphertext should show `AUTHENTICATED`, recover the original text, and report `PASS — untouched ciphertext recovered`.

The modified message is intentionally not displayed as a chat plaintext message. Its encrypted envelope is visible in the ciphertext table on both devices.
