// Copyright 2026 Zachary Fouts
// SPDX-License-Identifier: Apache-2.0

package secretscrub

// Version is the release this build of the package came from, in the form the
// module is tagged: a leading "v", then semver.
//
// # Why a library exports its own version
//
// A consumer that redacts data before shipping it has to be able to say WHICH
// redaction produced a given artifact, and no version is recoverable from the
// output: redaction is lossy on purpose, and [RedactedMarker] is the same
// string in every release. Go's build info does not answer it either — a
// dependency's version is absent from `debug.ReadBuildInfo` when the consumer
// is built with `-trimpath`, or vendored, or built from a replace directive,
// all of which are ordinary.
//
// The question is not hypothetical. v0.0.2 fixed a case where a credential
// placed in an identity field was published rather than redacted. Any artifact
// scrubbed by v0.0.1 is affected and any artifact scrubbed by v0.0.2 is not,
// and without a version recorded alongside the data the two are
// indistinguishable — which is exactly when somebody needs to tell them apart.
//
// So a consumer records this next to whatever it scrubbed, and a later reader
// can decide whether the artifact predates a fix.
//
// # Keeping it true
//
// This is a hand-maintained constant, and a hand-maintained version that drifts
// from the tag is worse than none: it would answer the question confidently and
// wrongly. TestVersionMatchesTheGitTag checks it against the repository's own
// tags, so a release that forgets to move it fails before it ships.
const Version = "v0.0.3"
