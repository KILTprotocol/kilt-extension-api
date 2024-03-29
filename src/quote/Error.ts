/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

export declare class QuoteError extends Error {}

export declare class HashMalformedError extends QuoteError {
  constructor(hash?: string, type?: string)
}

export declare class QuoteUnverifiableError extends QuoteError {}
export declare class SignatureUnverifiableError extends QuoteError {}
export declare class DidSubjectMismatchError extends QuoteError {}
