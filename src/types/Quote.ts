/**
 * Copyright (c) 2025, Built on KILT.
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
  issuerDid: Did
  cTypeHash: CTypeHash
  cost: ICostBreakdown
  currency: string
  timeframe: string
  termsAndConditions: string
}

/**
 * Signed quote from issuer
 */
export interface IQuoteIssuerSigned extends IQuote {
  // Signature of the issuer
  issuerSignature: DidSignature
}

/**
 * If the holder accepts the quote from the issuer, the holder counter-signs it
 */
export interface IQuoteAgreement extends IQuoteIssuerSigned {
  // Attached credential hash for linking the Quote to the credential that it refers to
  rootHash: ICredential['rootHash']
  holderDid: Did
  // The signature of the holder.
  holderSignature: DidSignature
}
