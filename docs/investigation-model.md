# Investigation Decision Model

Wireclaw is designed to answer troubleshooting questions, not merely enumerate packet anomalies.

## 1. Investigation stages

Every investigation follows this conceptual sequence:

1. **Can this capture answer the question?**
2. **What traffic is relevant to the symptom?**
3. **What directly observable conditions exist?**
4. **Which conditions could materially explain the user impact?**
5. **What competing explanations remain?**
6. **What conclusion is justified?**
7. **What evidence would resolve the remaining uncertainty?**

The system may revisit stages 2–5 iteratively, but capture-quality assessment always occurs first.

## 2. Symptom families

The free-text symptom is classified only to guide evidence selection; it is not itself evidence.

Initial symptom families:

- slow / latency / poor performance
- intermittent / random / occasional
- disconnect / reset / timeout
- cannot connect / failure
- throughput / bandwidth
- DNS / name resolution
- TLS / certificate / handshake
- unknown / general investigation

Multiple families may apply.

## 3. Candidate traffic selection

Candidate conversations should be ranked using a combination of:

- addresses/hostnames/ports explicitly mentioned by user
- protocol relevance
- temporal overlap with reported time window when supplied
- connection failures/resets
- retransmission/error signals
- unusually long transaction timing
- traffic volume/duration
- DNS/TLS/application relationships

Do not use highest byte count as the sole relevance criterion.

## 4. Slow-path decision model

For a "slow" symptom, attempt to establish the following sequence for each relevant transaction/conversation.

### 4.1 Name resolution

Questions:
- was DNS required?
- how long did the relevant resolution take?
- were there retries/failures/fallbacks?

Possible outcome:
- DNS materially contributes
- DNS normal/insignificant
- DNS not observable/not applicable

### 4.2 Connection establishment

Questions:
- how long from SYN to established TCP?
- were SYNs retransmitted?
- did connection attempts fail before success?

### 4.3 TLS establishment

Questions:
- how long after TCP establishment until usable TLS session state?
- were there repeated handshakes or failure alerts observable?

### 4.4 Transport health

Questions:
- what is measured RTT?
- are retransmissions/duplicate ACKs material?
- is reordering a better explanation than loss?
- are receive windows constraining sender progress?
- are resets/reconnections extending elapsed time?
- do packet-size/MSS/fragmentation/ICMP signals support PMTUD/MTU involvement?

### 4.5 Request-to-response timing

When protocol visibility allows:
- identify request completion
- identify first response data
- measure wait
- compare wait with transport RTT/loss conditions

A long wait with prompt ACKs and otherwise healthy transport may support a server/application fault-domain finding. It does not prove which backend component behind the server caused the delay.

### 4.6 Transfer phase

Questions:
- once response begins, is data delivered continuously?
- what throughput/goodput is achieved?
- are stalls explained by retransmission, receiver window, RTT, or sender inactivity?

## 5. Fault-domain reasoning

Wireclaw evaluates support for these domains:

### Client

Examples of supporting evidence:
- client delays initiating request/connection after prior dependency completes
- client advertises zero/tiny receive window
- client resets otherwise healthy connection

### Local/network path

Examples:
- high RTT
- retransmission/loss indicators affecting progress
- repeated connection setup failures
- fragmentation/PMTUD evidence

Packet capture alone may not identify the physical hop where path loss occurred.

### Server/application

Examples:
- request delivered/acknowledged promptly
- no material transport impairment
- long interval before server response data

This boundary includes downstream dependencies behind the observed server unless additional evidence localizes them.

### DNS

Examples:
- long query response times
- retries/timeouts
- resolver failure/fallback materially delaying connection

### Capture/observability

Examples:
- missing direction
- capture begins midstream
- dropped/truncated packets
- timestamp quality prevents useful timing

### Unknown

Used when available evidence does not discriminate sufficiently.

## 6. Evidence sufficiency rules

A finding should not be high confidence merely because one anomaly exists.

High-confidence diagnostic findings generally require:
- relevant traffic scope established
- capture quality adequate for the conclusion
- direct/derived evidence of the condition
- demonstrated plausible relationship to user impact
- material competing explanations considered

Examples:

### Retransmissions

Incorrect conclusion:
- "31 retransmissions means the network is the root cause."

Better reasoning:
- quantify retransmission rate
- identify whether retransmissions delay relevant data
- inspect duplicate ACK/reordering context
- compare with response wait/RTT
- state that capture perspective may not localize where loss occurred

### Server delay

Incorrect conclusion:
- "2.5 seconds before response proves the server CPU is slow."

Better reasoning:
- request is delivered and acknowledged
- transport appears healthy
- 2.5 seconds elapse before application response data
- therefore delay is at or behind server/application boundary
- CPU/database/API cause requires additional server-side evidence

### MTU

Incorrect conclusion:
- "large packets plus slowness means MTU issue."

Better reasoning requires supporting signals such as:
- MSS/packet-size pattern
- repeated failure of larger segments
- ICMP fragmentation-needed/Packet Too Big when visible
- successful smaller traffic while larger transfer stalls
- appropriate caveats when ICMP/path visibility is absent

## 7. Ambiguous-pair tests

The investigation model must explicitly differentiate look-alike conditions.

### High RTT vs server wait

Discriminator:
- transport RTT and ACK timing versus request-to-first-response interval

### Loss vs reordering

Discriminator:
- duplicate ACK patterns, sequence progression, retransmission timing, out-of-order indicators

### Capture loss vs network loss

Discriminator:
- capture quality/drop metadata, sequence visibility, capture location, evidence from opposite endpoint when available

### Receive-window stall vs server think time

Discriminator:
- advertised receive window and sender ability to transmit versus idle period after request acknowledgement

### DNS delay vs TCP delay

Discriminator:
- query/response interval versus SYN/SYN-ACK interval

### MTU/PMTUD vs generic loss

Discriminator:
- size-dependent failure and fragmentation/ICMP/MSS evidence

If the discriminator is not present, Wireclaw should report the ambiguity and recommend the specific next evidence.

## 8. Next-evidence recommendations

Recommendations should be diagnostic, not generic.

Examples:

- "Capture simultaneously at the server to determine whether retransmissions reflect loss before or after the server interface."
- "Collect a browser HAR for the same reproduction to align user-visible request timing with the packet transaction."
- "Collect load-balancer/backend timing for transaction X; the PCAP localizes delay behind the server boundary but cannot identify the backend dependency."
- "Collect interface drop/error counters during the reproduction to test whether local egress/ingress loss explains the observed retransmissions."
- "Capture the TCP handshake; the existing trace starts midstream and cannot establish connection-setup delay."

Avoid vague recommendations such as "check the network" or "check the server."

## 9. Model reasoning output

The reasoning provider may output:
- hypothesis proposals
- requested capability calls
- evidence-ID references
- explanation drafts
- next-evidence suggestions

It may not output authoritative packet facts independent of normalized evidence.

The application validates final findings against case evidence before presentation.
