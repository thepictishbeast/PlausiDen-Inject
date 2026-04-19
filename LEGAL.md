# Legal Considerations — PlausiDen-Inject

`plausiden-inject` writes synthetic artifacts into real OS data
stores on the user's own device — Firefox's `places.sqlite`,
Chrome's `History`, Android ContentProviders, macOS Notes /
Safari, Windows registry / Jump Lists. This document summarizes
the publicly-known legal posture of that specific capability.

This is **not legal advice.** Consult licensed counsel before
deploying Inject in any context with legal stakes.

Required per v1.2 §G.2. Paired with `OPSEC.md` in this repo;
cross-reference with `PlausiDen-Browser-Ext/LEGAL.md` for the
ring-0 browser-extension variant and `PlausiDen-USB/LEGAL.md` for
the hardware-device variant.

Authored: Claude 3, 2026-04-17.

---

## 1. Scope of this document

Covers three questions specific to Inject:

1. **Is it legal to write synthetic data into my own device's
   data stores?** (§2)
2. **Does doing so create civil or criminal liability in
   litigation contexts?** (§3)
3. **Does the data written by Inject itself constitute evidence
   of anything?** (§4)

Does NOT cover:

- Legal posture of possessing / installing the software —
  governed by browser-extension / Desktop-app laws where
  applicable (see sibling LEGAL.md docs).
- Constitutional challenges to forensic-tool use generally
  (that's the `LEGAL.md` in Browser-Ext §2.2).
- Tax / insurance / professional-licensing obligations.

---

## 2. Writing to your own device's data stores

### 2.1 United States

The central statute is **18 U.S.C. § 1030** (Computer Fraud and
Abuse Act). § 1030 prohibits:

- Accessing a "protected computer" without authorization, or
- Exceeding authorized access to obtain information.

Installing Inject on your own device and running it to modify
your own browser history is explicitly authorized — you are the
device owner. *Van Buren v. United States*, 593 U.S. ___ (2021)
narrowed the "exceeds authorized access" clause specifically so
that using your own device for purposes the *device owner*
permits is not CFAA liability, even if it violates a
service-provider's terms of service.

**18 U.S.C. § 1001** (false statements) and **18 U.S.C. § 1519**
(destruction of records in federal investigations) are
potentially implicated only when Inject runs in a specific-intent
context — see §3 below.

### 2.2 European Union

GDPR Article 4(1) defines "personal data" as information relating
to an identified or identifiable natural person. Inject writes
**synthetic** data about fabricated personas; that data does not
relate to real people (other than the user, whose own device it
is). The user acts in the role of "data subject" *and* "processor"
simultaneously, on their own data, which is GDPR-trivial.

Member-state variations on computer-abuse statutes (German
*Strafgesetzbuch* §§ 202a-202c, French *Code pénal* Art. 323-1 et
seq., UK *Computer Misuse Act 1990*) follow the same
authorization-based framework as CFAA. Writing to one's own device
is authorized by definition.

### 2.3 Other jurisdictions

Most jurisdictions treat device-owner writes to their own data as
legal. Notable exceptions:

- **Singapore** — the *Computer Misuse Act 1993* has been
  interpreted broadly; consult local counsel.
- **UAE** — the *Federal Decree Law No. 34 of 2021* (Combating
  Rumours and Cybercrimes) contains broad "information
  falsification" language that could be applied creatively.
- **China** — *Cybersecurity Law of 2017* + recent
  "data-integrity" regulations may consider deliberate data
  falsification a crime in some circumstances.
- **Russia** — broad anti-extremist and "reliable information"
  statutes make deployment risky.

See `OPSEC.md` §authoritarian for do-not-deploy guidance.

---

## 3. Running Inject during known litigation / investigation

The **specific-intent** question is where Inject could create real
liability. Running Inject as routine hygiene (daily background
service, over months or years) is analogous to running any privacy
tool — not targeted at any proceeding.

Running Inject in response to a known subpoena, investigation, or
preserved-evidence hold raises serious concerns:

### 3.1 Obstruction of justice (US)

**18 U.S.C. § 1512** (tampering with records in official
proceedings) prohibits altering records with intent to impair
their use in an official proceeding.

The statute requires:

- **Knowledge** of an official proceeding.
- **Intent** to impair the record's use in that proceeding.
- **Alteration** of the record.

Writing synthetic entries into a database you already have
authorization over is "alteration." Doing so with knowledge of a
pending federal investigation and intent to frustrate it is the
fact pattern § 1512 targets. Penalty: up to 20 years.

**Practical rule:** if you know of a federal investigation touching
your browsing / filesystem / communications history, consult
counsel before running Inject in any mode — pause, continue, or
uninstall — because even the act of pausing can be framed as
intentional alteration of the record's state.

### 3.2 Spoliation of evidence (civil, US)

Once a litigation hold attaches (reasonable anticipation of
litigation), a party has a duty to preserve potentially-relevant
evidence. A court may impose adverse-inference sanctions or
terminating sanctions for spoliation.

Inject's writes during a hold window could be framed as:

- Destruction (overwriting organic data with synthetic),
- Obstruction (making organic data harder to isolate),
- Or neither, if the court finds the writes were routine and
  well-documented in advance.

**Practical rule:** document Inject deployment dates BEFORE any
hold attaches. A log of "Inject running continuously since
2025-06-12" is defensible; a log of "Inject enabled 2026-04-15
after complaint served 2026-04-14" is not.

### 3.3 Destruction or removal of property to prevent seizure

**18 U.S.C. § 2232** — narrow. Applies to federal seizure
authority. Unlikely to reach Inject unless the specific federal
agency has declared intent to seize and Inject is run in the
window between declaration and execution.

### 3.4 International equivalents

- **UK Criminal Justice and Police Act 2001** and
  *Criminal Procedure Act 1995* (Scotland) contain obstruction
  language. Consult local counsel.
- **French Code pénal** Art. 434-4 (obstructing the
  administration of justice) — specific-intent required.
- **EU Framework Decision 2003/577/JHA** on asset-freezing
  orders — applies to frozen assets, not routine device data.

---

## 4. Is data written by Inject itself evidence?

This is the **reverse** of the §3 question. In a proceeding where
opposing counsel knows or suspects Inject was running, the
written-by-Inject data itself becomes a discoverable record.
Consequences:

- **Adverse-inference arguments cut both ways.** A court may
  accept "all of this history is unreliable because Inject was
  running" (good for the defense) or "this user deliberately ran
  a tool to corrupt evidence" (bad for the defense, depending on
  specific-intent evidence).
- **Disclosure obligations.** A party who knows Inject ran may be
  required to disclose it under Rule 26(a) discovery. Failure to
  disclose a discoverable fact can result in exclusion,
  sanctions, or case-terminating orders.
- **Expert-witness cost.** Explaining Inject to a jury typically
  requires an expert witness. Budget accordingly.

**Practical rule:** disclose Inject's presence in discovery if it's
running on any device relevant to the proceeding. The reliability-
challenge argument is stronger when volunteered than when
discovered.

---

## 5. Platform-specific legal notes

### 5.1 Firefox places.sqlite writes (Linux/macOS/Windows)

Firefox's license (MPL 2.0) governs Firefox, not Inject's use of
Firefox's data format. Writing to places.sqlite doesn't violate
the MPL. The write is a database operation on data the OS attributes
to the user, not a modification of Firefox itself.

### 5.2 Chrome History writes

Chrome's ToS does not prohibit third-party tools from modifying
the local profile's History DB. (Chrome does detect tampered
profiles in some contexts and will offer to "repair" them — which
would undo Inject's writes. Disable auto-repair via enterprise
policy or manage via the Desktop host.)

### 5.3 Android ContentProvider writes

The Android app holding the Inject capability must declare the
permissions it uses (READ_HISTORY_BOOKMARKS, WRITE_CONTACTS,
etc.). Declaring and using permissions the user granted is inside
Android's security model. The user's explicit installation of the
app + grant of permissions is the authorization.

### 5.4 macOS / Windows / iOS (scaffold)

See per-platform OPSEC.md sections. Legal posture mirrors the
general "device-owner writes own data" framework.

---

## 6. Prairie Land and the notification-cache question

In *In re Prairie Land Cooperative* (N.D. Iowa, 2019) and related
cases, notification cache data was admitted as evidence of
conversations that were never contemporaneously observed — the
cache persists messages the user never actually saw. Inject's
`engine-comms::notifications` module (when it lands, task #25)
specifically targets this forensic pathway: injecting synthetic
notifications with plausible sender/timestamp/preview data that
looks like what Prairie Land-era evidence relies on.

Running the notifications module while a Prairie Land-style
discovery is underway is the paradigm case for §3.1 obstruction
concerns. Do not enable on any device subject to such a pending
action without counsel.

---

## 7. Citations — primary sources

- 18 U.S.C. § 1030 (Computer Fraud and Abuse Act).
- 18 U.S.C. § 1001 (False Statements).
- 18 U.S.C. § 1512 (Obstruction of Official Proceedings).
- 18 U.S.C. § 1519 (Destruction of Records in Federal
  Investigations).
- 18 U.S.C. § 2232 (Destruction/Removal to Prevent Seizure).
- *Van Buren v. United States*, 593 U.S. ___ (2021).
- *Riley v. California*, 573 U.S. 373 (2014).
- *Carpenter v. United States*, 585 U.S. 296 (2018).
- Regulation (EU) 2016/679 (GDPR), Articles 4, 6, 25.
- StGB (Germany) §§ 202a-202c.
- Code pénal (France) Art. 323-1 et seq., 434-4.
- Computer Misuse Act 1990 (UK).
- *In re Prairie Land Cooperative* (N.D. Iowa 2019) — notification
  cache admissibility.
- Federal Rules of Civil Procedure 26, 37 (discovery, spoliation
  sanctions).

Case law specific to "device-owner running anti-forensic injection
on own device" is extremely thin as of 2026. The citations above
are the closest analogues and will evolve.

---

## 8. What this document does not cover

- **Specific litigation strategy.** Retain counsel.
- **Foreign evidence-sharing treaties** (MLAT, Budapest Convention
  on Cybercrime). Cross-border discovery may reach Inject logs
  even if the device never leaves the user's jurisdiction.
- **Professional-licensing obligations.** Attorneys, doctors,
  accountants, and regulated-industry professionals have duty-of-
  record obligations that may prohibit Inject's use during
  active representation / treatment / audit periods.
- **Insurance policy exclusions.** Some cyber-insurance policies
  exclude claims involving "intentional data alteration." Check
  your policy before deploying.
- **Whistleblower-protection posture.** Whistleblower statutes
  generally do not extend to evidence-integrity questions. The
  protected act is the disclosure; the evidence supporting it
  must still be authentic.

This document will be updated as case law develops. File an issue
or PR with new citations.
