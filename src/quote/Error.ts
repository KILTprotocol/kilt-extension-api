/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

export class QuoteError extends Error {}

export class HashMalformedError extends QuoteError {}

export class QuoteUnverifiableError extends QuoteError {}
export class SignatureUnverifiableError extends QuoteError {}
export class DidSubjectMismatchError extends QuoteError {}
