# connect-messaging

Finds out why DIDComm messages between two mediated peers don't arrive, by sending
probes through the mediator and collecting whatever comes back.

It gives itself a throwaway identity, mediates it with the mediator
(`coordinate-mediation/3.0`: `mediate-request` → `mediate-grant` → `recipient-update`),
sends, then polls its own queue (`messagepickup/3.0` `delivery-request` →
`messages-received`), logging every reply and the envelope it arrived in: JSON JWE,
COSE, or the pre-COSE "JWE in a CBOR map" layout. That envelope also says roughly
which library version the replying peer runs.

```sh
cargo run -p didcomm-diagnostic-connect-messaging -- <MODE> [OPTIONS]
```

| Mode | Sends | Rules in or out |
|---|---|---|
| `selftest` | to its own DID, in JSON and in COSE; and to a DID nobody registered | Whether the mediator round trip works at all, and how the mediator answers a forward for a recipient it doesn't know. |
| `control` | to a second, JSON-first DID of its own, registered like any other | Whether a JSON-first `accept` list (`["didcomm/v2", "didcomm/v2+cbor"]`, what older library versions minted) is a problem in itself. |
| `send` | each `--target` a `discover-features` query and a `user-profile` (with `send_back_yours`), once in JSON and once in COSE | Whether the target's app receives, reads and answers, and in which encoding it answers. |
| `matrix` | each `--target`, plus its own two DIDs as controls, a basic message in every inner × forward encoding combination; the message text names the combination | Which combinations reach a target, as the person can see in their app: "This message was sent over (JSON) (CBOR Forward)". |

Options:

- `--target NAME=DID`: a DID to probe; repeat for several. Use the long-form `did:peer:4`.
- `--wait SECONDS`: how long to poll for replies after sending.
- `--identity PATH`: where the diagnostic identity is kept (default
  `connect-messaging.identity.json`). Reusing it collects replies to an earlier run.
  **It holds private keys**: keep it out of version control.
- `--mediator DID`: defaults to `did:web:mediator.wyvrn.app`.
- `--name NAME`: the display name the `send` mode's profile probes carry.

The DIDs this probes are given on the command line only; none are kept in this folder.

## Reading the results

- **An HTTP 200 from the mediator proves nothing about delivery.** A mediator queues a
  forward only for a recipient DID it has a registration for and drops the rest,
  answering 200 either way. `selftest` shows this with a DID nobody registered.
- **Your own DIDs arrive, a target's don't, in every encoding**, including JSON, which
  every version reads: the target's DID isn't registered with the mediator. Fix it on
  the target's side by registering it again (in wyvrn-chat: restart the app on a
  version that renews its registrations, or a soft remint from Settings → Developer).
- **The target answers, but in an envelope your side can't read** (an `UNREADABLE`
  line): the two sides run library versions with incompatible `didcomm/v2+cbor`
  layouts. The fingerprint says which: `legacy JWE-in-a-CBOR-map` comes only from a
  library from before CBOR became COSE.
- **`control` arrives but the target doesn't, and both are JSON-first**: the `accept`
  order isn't the cause.

## Side effects on the people you probe

`send` and `matrix` deliver real messages. A wyvrn-chat user will see a new contact
named after `--name` (with "(JSON)" or "(CBOR)" appended, the last profile winning)
and, from `matrix`, up to four short messages. They're safe to delete. Ask before
probing someone else's DID.

## What it found the first time

Written while diagnosing two wyvrn-chat users who could not reach each other on
`mediator.wyvrn.app`:

1. `selftest`: the mediator answered 200 for an unregistered DID.
2. `send`: neither user answered anything, JSON included, with both apps open.
3. One user rotated their identity (revoking devices), which re-registers it; `send`
   then got every reply, in COSE, within two seconds.
4. `control`: a registered JSON-first DID received everything, so the `accept` order
   wasn't the cause.
5. `matrix`: the rotated user saw all four messages, the other none.

The cause was a missing mediator registration for the second user's Identity DID.
wyvrn-chat registered its DIDs only when minting them, so it never recovered; it now
renews them on every start.
