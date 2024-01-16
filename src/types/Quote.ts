/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { DidSignature, Did, ICredential, CTypeHash } from '@kiltprotocol/types'

/**
 * Interface to break down the costs for a quote.
 */
export interface ICostBreakdown {
  tax: Record<string, unknown>
  net: number
  gross: number
}
export interface IQuote {
  attesterDid: Did
  cTypeHash: CTypeHash
  cost: ICostBreakdown
  currency: string
  timeframe: string
  termsAndConditions: string
}

/**
 * Signed quote from attester
 */
export interface IQuoteAttesterSigned extends IQuote {
  // Signature of the attester
  attesterSignature: DidSignature
}

/**
 * If the claimer accepts the quote from the attester, the claimer counter-signs it
 */
export interface IQuoteAgreement extends IQuoteAttesterSigned {
  // Attached credential hash for linking the Quote to the credential that it refers to
  rootHash: ICredential['rootHash']
  claimerDid: Did
  // The signature of the claimer.
  claimerSignature: DidSignature
}
