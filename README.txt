███╗   ███╗ ██████╗ ███╗   ██╗ ██████╗ ██╗     ██╗████████╗██╗  ██╗
████╗ ████║██╔═══██╗████╗  ██║██╔═══██╗██║     ██║╚══██╔══╝██║  ██║
██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║██║     ██║   ██║   ███████║
██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██║   ██╔══██║
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ██║   ██║  ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝


  ░▒▓█ _concentrator_ █▓▒░
  The MONOLITH hub. Every frame passes through it, so it keeps the rules.

  ───────────────────────────────────────────────────────────────
  ▓ WHAT IT DOES
  The bus's one server: nodes connect to it over WebSocket with mutual TLS,
  and it passes frames between them — only where they are addressed, and
  only if their sender may send them. SPEC.txt §26, SECURITY.txt §5.

  ▪ **Identity.** Every connection is a client certificate issued by the
    bubble CA — the one CA the hub trusts — and named in the policy. It may
    speak as that node, and a panel also as <node>.<person>. A frame
    claiming anyone else is dropped. A node is one certificate's and holds
    one connection: a second, while the first is up, is refused and logged
    as an ERROR — a copy of the node's key, or the node restarted before
    its old connection went silent (it is dropped within 75 s).
  ▪ **Permission.** Each node may send the requests its policy line lists,
    besides answering what it is asked and announcing its own PUB and REG.
  ▪ **Tickets.** A panel may do nothing but sign in until it shows a ticket
    marshal signed for its person (CONCENTRATOR:SET:TICKET). Then it may
    send what the ticket's grants cover, every frame naming the person, and
    hears only the announcements they cover. A ticket lasts ten minutes at
    most and says when it was signed. When marshal ends a person's tickets
    (CONCENTRATOR:STOP:TICKETS:<person>:<since>) the hub drops the
    connections holding one and refuses any signed until then, shown again;
    it refuses too a ticket signed before it started, in the future, or
    claiming more than ten minutes.
  ▪ **Addressing.** A request reaches its addressee only. A reply reaches
    only the connection that asked — the hub remembers each request's id —
    and a reply nobody asked for goes nowhere. An announcement (PUB, REG,
    FIRE) reaches the nodes whose line lists it after `hears`, and the
    panels whose ticket covers it.
  ▪ **One reading.** v2 only: a v1 frame is dropped. A frame with anything
    around it but one line ending is dropped, and what goes on is exactly
    the bytes that were checked.
  ▪ **Limits.** Frames of 4096 bytes at most (a larger one drops the
    client); a rate per connection, and one for all the connections of a
    panel's certificate together (500 a second); 64 connections per panel
    certificate and 1024 panel connections in all (a node is never refused
    for room); a ticketed panel's PING only PING:PING, and its roll calls
    one in five seconds; revoked certificates refused, and expired ones
    dropped the moment they expire; a client silent for 75 s — the hub
    pings every 30 — dropped. A client whose queue is full loses frames,
    not its place, and whoever asks it something meanwhile is told BUSY;
    one that has stopped reading is dropped by its writer's 5-second
    deadline, so no client stalls the hub. A request carrying an Origin
    header, which only a web page sends, is refused.
  ▪ **Silence about contents.** Frames are never logged. A refusal is
    logged as DROPPED with the sender's certificate, the reason, the verb,
    the noun and the addresses — never the arguments, which hold tokens,
    proofs and messages.

  ───────────────────────────────────────────────────────────────
  ▓ THE POLICY
  One line per certificate — see `policy.example`:

    <certificate CN>  <node>  node   [<may send>...]  [hears <announcement>...]
    <certificate CN>  <node>  panel

    achtung    ACHTUNG    node    ALL.FIRE.* VERTEX.SET.BUZZ.STATE
    synapse    SYNAPSE    node    MARSHAL.GET.PEOPLE    hears MARSHAL.PUB.PEOPLE
    portal     MONOWEB    panel

  A pattern is written as a grant is: an action, or a prefix of one ending
  in "*" — TO.VERB.NOUN for what a node sends, FROM.VERB.NOUN for what it
  hears. A certificate not listed cannot connect, and a node may be listed
  once. A panel's line lists nothing: what it may send and hear comes from
  its person's ticket.

  Revoked certificates: a file of serials, one per line, in hex as openssl
  prints them (`openssl x509 -noout -serial -in <cert>`). On the server,
  `sudo monolithctl revoke <name|serial>` writes it and reloads the hub.

  After changing either: `kill -HUP` the concentrator. It reads both again
  and drops at once whoever they no longer admit as they were; a policy
  that does not parse is refused and the old one stays.

  ───────────────────────────────────────────────────────────────
  ▓ BUILD & RUN
    go build -o bin/concentrator ./cmd/concentrator
    go test ./...

  It will not start without mutual TLS and a policy:

    ./bin/concentrator -p 8443 \
      --tls-cert ../pki/concentrator/concentrator.cert.pem \
      --tls-key ../pki/concentrator/concentrator.key.pem \
      --tls-client-ca ../pki/intermediate/certs/intermediate.cert.pem \
      --policy policy \
      --ticket-key ../marshal/ticket.pub

  The client CA file holds the CA that issues the bus's certificates and
  nothing else - not the chain, not the root - and that CA must be
  pathlen:0. Anything else and the hub will not start: whatever CA it
  trusts could issue a certificate named marshal. On the server,
  monolithctl points it at /etc/monolith/ca/bubble-ca.crt.

  ───────────────────────────────────────────────────────────────
  ▓ CONFIGURATION
  Flags, with `.env` in the working directory supplying defaults:

    -p, --port          CONCENTRATOR_PORT            8443
        --tls-cert      CONCENTRATOR_TLS_CERT        the hub's certificate
        --tls-key       CONCENTRATOR_TLS_KEY         its key
        --tls-client-ca CONCENTRATOR_TLS_CLIENT_CA   the one CA of client certificates
        --policy        CONCENTRATOR_POLICY          policy
        --revoked       CONCENTRATOR_REVOKED         (none)
        --ticket-key    CONCENTRATOR_TICKET_KEY      ticket.pub — marshal's public key
    -l, --log           CONCENTRATOR_LOG             info

  TLS 1.3 only: every client on the bus is Go. Whether ukaz's library gets
  1.2 is decided when it joins. Logs go to standard output, for the
  journal; there is no log file.
  
  ───────────────────────────────────────────────────────────────
  ▓ FINAL WORDS
  Small hub, big fan-out.
