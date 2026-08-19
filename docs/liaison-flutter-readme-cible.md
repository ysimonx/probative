# README cible de la liaison Flutter

**Statut : cible d'API, aucune ligne de code n'existe.** Ce document est le brouillon du
README que le plugin Flutter publiera sur pub.dev. Il est écrit *avant* l'implémentation,
et c'est voulu : il sert d'étalon de complexité d'intégration — combien de gestes, combien
de lignes, combien de comptes à provisionner pour qu'une application quelconque obtienne
une prise de vue à valeur probante. Si l'implémentation ne peut pas tenir ce README, c'est
une décision à instruire, pas un détail à absorber en silence.

Ce qu'il fige n'est pas inventé ici. Chaque forme d'API traduit une décision déjà prise :

- **ADR-0003** — pont mince : le chemin critique est natif, Dart ne reçoit que l'enveloppe
  signée, opaque, et les octets traversent une fois, après scellement, par chemin de fichier ;
- **ADR-0008** — le cœur possède la session de capture, la vue Flutter s'y rattache en
  consommateur ; d'où le widget `ProbativePreview(session:)` et l'interdiction d'un
  contrôleur caméra parallèle ;
- **le test de la couture** (`acquisition-et-liaisons.md` §1) — le chemin `capture` tient
  en **un seul appel**, `session.capture()` ;
- **ADR-0009 / 0010 / 0011** — séries, hors ligne, validation différée : présentés en
  « preview », l'API de campagne étant la moins stabilisée ;
- **invariants 1 et 5** — aucun booléen de confiance sur l'appareil, verdict structuré par
  propriété, rendu par le serveur de l'intégrateur.

Le README est en anglais parce que pub.dev l'est ; le nom `probative` est un tenant-lieu
dont la disponibilité sur pub.dev **et** npm reste à vérifier (ADR-0003). Les versions
minimales de plateforme (API 26, iOS 14) sont des cibles plausibles, pas des mesures.

---

# probative

Sealed, hardware-attested captures for Flutter — and a server-side verifier that
judges them.

An ordinary geotagged photo proves nothing: EXIF is editable, GPS is spoofable
with a consumer app, and coordinates burned into pixels are just pixels. When a
decision depends on a capture, you need evidence that holds up. `probative`
produces a **sealed evidence envelope** establishing that an image was taken
**by this sensor, at this place, at this time, on a device that was not
compromised** — and a verifier your server runs to judge it.

The device never grades itself. Your server does.

## What you get

- **One call from shutter to sealed proof.** `session.capture()` returns a photo
  whose bytes were hashed, bound to a server nonce, and signed by a hardware key
  before they ever reached Dart. Nothing on the Dart side can alter the proof —
  by construction, not by discipline.
- **Hardware attestation on both platforms.** Play Integrity + hardware key
  attestation on Android, App Attest on iOS. Same envelope format, same
  verifier, same grading — the format reasons in properties, not platforms.
- **A camera preview widget** that attaches to the capture pipeline as a
  consumer. What you see is the sensor the proof is about.
- **A structured verdict, never a boolean.** The verifier grades each property
  (`integrity`, `origin`, `time`, `position`, `media`) and always tells you
  *why* — every level comes with a machine-readable reason.
- **Offline capture series** *(preview)* — pre-fetched nonces, tamper-evident
  chaining across shots, and deferred validation when the network returns.

## How it works, in 30 seconds

1. Your server issues a single-use **nonce**.
2. The native core captures the photo, computes a challenge
   `SHA-256(payload ‖ nonce)`, has the platform attest it (Play Integrity /
   App Attest), collects position and motion evidence, and signs everything
   with a key that never leaves the device's secure hardware.
3. Dart receives the sealed envelope (opaque bytes) and the photo file. You
   ship both to your server.
4. The verifier recomputes every binding — it never trusts a field it can
   recompute — and returns a graded verdict.

The client **collects and signs**; the server **judges**. There is no
`isTrusted` flag anywhere in the client API, and that is a feature: any
on-device boolean would be exactly as forgeable as the EXIF data this library
exists to replace.

## Requirements

| | Android | iOS |
|---|---|---|
| OS | Android 8.0+ (API 26, target — TBC) | iOS 14+ (target — TBC) |
| Hardware | Real device with hardware-backed keystore | Real device (App Attest is unavailable in Simulator) |
| Services | Google Play services | — |
| Account setup | A Google Cloud project number (Play Integrity) | Apple Developer Program (paid — App Attest requires it) |
| Distribution | Any. Play distribution raises the `origin` grade | Any. TestFlight/App Store use the production attestation environment |
| Server | Python 3.11+ for the verifier, or any host for its container | same |

Emulators and simulators run the code but cannot produce hardware attestation:
the verifier will grade such envelopes accordingly. Plan your integration
testing on real devices from day one.

## Getting started

### 1. Add the dependency

```yaml
dependencies:
  probative: ^0.1.0
```

### 2. Platform setup

**Android** — no manifest changes required; the plugin declares the camera and
location permissions it needs. Two account-level facts must reach the plugin at
runtime (they are account data, never hardcoded in a repo):

- your **Google Cloud project number**, with the Play Integrity API enabled;
- awareness that Play Integrity has **per-app daily quotas**: N devices × M
  captures/day is your call volume. Check the defaults against your expected
  scale before launch.

**iOS** — in Xcode:

- add the **App Attest** capability to your target;
- add `NSCameraUsageDescription` and `NSLocationWhenInUseUsageDescription` to
  your `Info.plist`.

### 3. Deploy the verifier

The verifier is a Python package your backend runs — envelopes are judged on
*your* infrastructure, and captures never transit through anyone else's.

```bash
pip install probative-verifier   # name TBC
probative-verifier serve --port 8765
```

It exposes three routes: device enrollment, nonce issuance, and envelope
verification. Authentication between your app and this server is your
deployment's business (a session token, mTLS, anything): the envelope
authenticates *itself*, so channel security never enters the verdict — and the
proof stays verifiable long after the session that carried it is gone.

## Usage

### Initialize once

```dart
import 'package:probative/probative.dart';

final probative = await Probative.initialize(
  ProbativeConfig(
    verifier: HttpVerifier(
      Uri.parse('https://verify.example.com'),
      // Called for every request; plug in your own auth.
      authorization: () async => 'Bearer ${await myApi.token()}',
    ),
    android: const AndroidOptions(cloudProjectNumber: '123456789012'),
  ),
);
```

Initialization enrolls the device on first run (hardware key generation +
attestation) and reuses the stable enrollment afterwards. You never manage
keys.

### Preview and capture

The core owns the camera session; your widget tree only displays it. Do **not**
run `camera.dart` or any other camera controller alongside — two owners of one
camera is the classic failure mode, and the proof is only about the pipeline
the core owns.

```dart
class CaptureScreen extends StatefulWidget {
  const CaptureScreen({super.key});
  @override
  State<CaptureScreen> createState() => _CaptureScreenState();
}

class _CaptureScreenState extends State<CaptureScreen> {
  ProbativeSession? _session;

  @override
  void initState() {
    super.initState();
    _open();
  }

  Future<void> _open() async {
    await probative.ensurePermissions(); // camera + location, upfront
    final session = await probative.openSession();
    setState(() => _session = session);
  }

  @override
  void dispose() {
    _session?.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final session = _session;
    if (session == null) return const Center(child: CircularProgressIndicator());
    return Stack(
      children: [
        ProbativePreview(session: session),   // a consumer of the core's session
        Align(
          alignment: Alignment.bottomCenter,
          child: ShutterButton(onPressed: () async {
            final capture = await session.capture();   // the one call
            // capture.mediaPath — the sealed photo, exactly as signed
            // capture.envelope  — opaque proof bytes; store or forward as-is
          }),
        ),
      ],
    );
  }
}
```

`capture()` is the entire proof path: nonce, shutter, sensor evidence,
attestation, signature. By the time the `Future` completes, the photo on disk
is already under seal. Keep the preview open between shots — the session warms
the sensor and the evidence collectors, and repeated captures are fast.

### Submit and read the verdict

```dart
final verdict = await probative.submit(capture);

switch (verdict.level) {
  case ProbativeLevel.strong:
  case ProbativeLevel.standard:
    await myApi.attach(capture.mediaPath, verdict);
  case ProbativeLevel.degraded:
    // Usable, with named weaknesses — decide per your policy.
    log(verdict.levelReason);
  case ProbativeLevel.rejected:
    // The reason is always actionable, never a bare "no".
    showRetryHint(verdict.levelReason);
}
```

You can also skip `submit()` entirely and move the envelope through your own
backend: it is a plain byte string with no coupling to any transport.

### Sealing your own bytes (the `core` profile)

If you need to own the camera — or the content is not a photo at all — seal
arbitrary bytes instead:

```dart
final envelope = await probative.seal(bytes); // profile: core
```

This is not a degraded mode; it is a *narrower claim*, honestly named. The
verifier will grade what can still be proven (device integrity, timing,
signature) and will not pretend to know how the content was acquired. That is
the whole difference between the two profiles: `capture` adds "the core
witnessed the acquisition".

## The verdict

A verdict is graded per property, carries the profile it was judged under, and
always names its reason:

```json
{
  "profile": "capture",
  "level": "STANDARD",
  "level_reason": "origin at grade B: recapture cap (capture profile)",
  "properties": {
    "integrity": "A",
    "origin":    "B",
    "time":      "A",
    "position":  "A",
    "media":     "A"
  },
  "flags": []
}
```

| Level | Meaning |
|---|---|
| `STRONG` | Every property at its highest grade for the profile |
| `STANDARD` | Solid evidence; at least one property below its ceiling, reason named |
| `DEGRADED` | Verifiable but materially weakened (e.g. wide nonce window offline) |
| `REJECTED` | A binding failed. The reason says which, and it is exploitable in support |

| Property | What it grades |
|---|---|
| `integrity` | Device and app integrity at attestation time (Play Integrity / App Attest, key attestation) |
| `origin` | How confidently the content comes from this device's sensor |
| `time` | Width of the measured time bracket around the capture (server nonce → judgment) |
| `position` | Quality and freshness of the position fix, cross-checked against motion evidence |
| `media` | Sensor-to-signature latency and payload conservation |

Two honest limits you should design around:

- **In the `capture` profile, `origin` is capped at grade B in v0.1** — so
  `STANDARD` is the expected best for photos. The cap exists because *analog
  recapture* (photographing a screen with an enrolled device) is not detected
  yet, and the format refuses to claim more than it can prove. `STRONG` is
  reachable in the `core` profile.
- **Grades follow measured quantities, never declared modes.** A capture with a
  stale position fix comes back with "position fix N ms old at shutter" — a
  number, not a mood. Build your UX on `level_reason`; it is designed to be
  shown, logged, and acted on.

## Rules that keep the proof valid

The seal covers the **exact bytes** the sensor produced. Anything that touches
them turns a valid proof into a rejection:

- **Never re-encode, resize, compress, rotate, or strip metadata from the
  photo file.** Upload it byte-for-byte. If your backend pipeline "optimizes
  images", exempt these files.
- **Never parse or rewrite the envelope.** It is opaque CBOR/COSE; treat it as
  a blob. Anything you need from it, the verdict already carries.
- **Never run a second camera stack next to a probative session.** One camera,
  one owner.
- **Don't invent client-side trust.** If you find yourself writing
  `if (looksValid)` on the device, you are rebuilding the thing this library
  exists to prevent.

## Offline capture series *(preview — API subject to change)*

For work sessions away from the network, a **campaign** opens by pre-fetching a
batch of single-use nonces; captures are then chained (each envelope commits to
the previous one, proving order and that none was removed), and everything is
graded on *measured* time windows once submitted:

```dart
final campaign = await probative.openCampaign(nonces: 40);
final session  = await campaign.openSession();
// ...captures as usual; chaining is automatic...
await campaign.submit(); // when the network is back: submit early, submit often
```

No network at the shutter is fine; no nonce at the shutter is not — a nonce
obtained *after* the shot would prove nothing, so a campaign without remaining
nonces refuses to capture rather than degrade silently. On Android, a deferred
attestation pass at submission recovers most of what offline capture could not
establish at shutter time. Expect wider time brackets — and therefore lower
`time` grades — the longer envelopes wait: the grade follows the measured
window, continuously.

## FAQ

**Why doesn't the plugin just tell me if a capture is trustworthy?**
Because any answer computed on the device could be forged by the same attacker
the system defends against. The client collects and signs; your server judges.
This is the design's first invariant, not an omission.

**Can I show my own viewfinder UI?**
Yes — the preview widget is just a consumer surface. Frame, overlays, shutter
button, whole screen design: yours. The camera *session* (sensor, format,
output) belongs to the core; that ownership is what makes the proof mean
something.

**Does it work on sideloaded builds / without Play?**
Yes. The envelope is produced and verifiable; the `origin` property simply
reflects what could be established about the binary's provenance. Play-
distributed builds grade higher because Google attests the binary.

**What data leaves the device?**
The photo and its envelope, to the verifier URL *you* configure — nothing else,
to no one else. Position data is inside the envelope; your app owns the user
consent story, and the plugin requests permissions only for what the `capture`
profile needs.

**What does this not protect against?**
Analog recapture: photographing a screen showing a fake scene, with a genuine
device, at a genuine place and time. The format names this blind spot instead
of hiding it, and caps the `origin` grade accordingly. Detection is on the
roadmap, not in v0.1.

**What is the envelope, technically?**
A COSE_Sign1 structure over a CBOR payload — content digest, capture claims,
sensor evidence — signed by a hardware-backed key, with the platform
attestation bound to `SHA-256(payload ‖ nonce)`. The full format is specified
in the repository (`docs/envelope-spec.md`), and the verifier recomputes every
binding rather than reading any of them.

## Integration cost at a glance

| Step | Where | Scope | Effort |
|---|---|---|---|
| Add dependency, initialize | `pubspec.yaml` + 1 Dart call | per app | minutes |
| Capture screen | your widgets + `ProbativePreview` | per app | ≈ 30 lines of Dart |
| Google Cloud project + Play Integrity API | Google Cloud / Play Console | per app | ~1 h, console work |
| App Attest capability + plist strings | Xcode | per app | minutes |
| Verifier deployment + auth wiring | your backend | per organization | ~1 day |
| Store distribution (full `origin` grade) | Play Console / App Store Connect | per app | your existing release process |

The Dart-side integration is deliberately small — if it ever needs more than
one call between shutter and sealed proof, that's a bug in *our* design, not a
step in yours. The irreducible costs are account-level: attestation services
only vouch for provisioned apps, and no library can wave that away.

## Status

`probative` is under active development and not yet published. The envelope
format (`probative/0.1`) is specified and exercised end-to-end by the native
cores on real devices (Android and iOS), with a Python verifier at 200+ tests.
This README describes the target plugin API; names and signatures may change
until 0.1.0.

License: Apache-2.0.
