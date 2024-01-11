/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/**
 * [[Quote]] constructs a framework for Attesters to make an offer for building a [[Claim]] on a [[CType]] in which it includes a price and other terms & conditions upon which a claimer can agree.
 *
 * A [[Quote]] object represents a legal **offer** for the closure of a contract attesting a [[Claim]] from the [[CType]] specified within the offer.
 *
 * A [[Quote]] comes with a versionable spec, allowing different [[Quote]] specs to exist over time and tracks under which [[Quote]] a contract was closed.
 *
 * @packageDocumentation
 */

import { dereference, signatureFromJson, verifyDidSignature } from '@kiltprotocol/did'
import type { Did, DidUrl, ICredential, SignerInterface } from '@kiltprotocol/types'
import { Crypto, JsonSchema, Signers } from '@kiltprotocol/utils'
import { IQuote, IQuoteAgreement, IQuoteAttesterSigned } from '../types/Quote.js'
import * as QuoteError from './Error.js'
import { QuoteSchema } from './QuoteSchema.js'

/**
 * Validates the quote against the meta schema and quote data against the provided schema.
 *
 * @param schema A [[Quote]] schema object.
 * @param validate [[Quote]] data to be validated against the provided schema.
 * @param messages The errors messages are listed in an array.
 *
 * @returns Whether the quote schema is valid.
 */
export function validateQuoteSchema(schema: JsonSchema.Schema, validate: unknown, messages?: string[]): boolean {
  const validator = new JsonSchema.Validator(schema)
  if (schema.$id !== QuoteSchema.$id) {
    validator.addSchema(QuoteSchema)
  }
  const result = validator.validate(validate)
  if (!result.valid && messages) {
    result.errors.forEach((error) => {
      messages.push(error.error)
    })
  }
  return result.valid
}

// TODO: should have a "create quote" function.

/**
 * Signs a [[Quote]] object as an Attester.
 *
 * @param quoteInput A [[Quote]] object.
 * @param signer A signer interface handling signing with the attester's authentication key.
 * @returns A signed [[Quote]] object.
 */
export async function createAttesterSignedQuote(
  quoteInput: IQuote,
  signer: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>
): Promise<IQuoteAttesterSigned> {
  if (!validateQuoteSchema(QuoteSchema, quoteInput)) {
    throw new QuoteError.QuoteUnverifiableError()
  }

  const signature = await signer.sign({
    data: Crypto.hash(Crypto.encodeObjectAsStr(quoteInput)),
  })
  return {
    ...quoteInput,
    attesterSignature: { signature: Crypto.u8aToHex(signature), keyUri: signer.id },
  }
}

/**
 * Verifies a [[IQuoteAttesterSigned]] object.
 *
 * @param quote The object which to be verified.
 * @param options Optional settings.
 * @param options.dereferenceDidUrl Resolve function used in the process of verifying the attester signature.
 */
export async function verifyAttesterSignedQuote(
  quote: IQuoteAttesterSigned,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<void> {
  const { attesterSignature, ...basicQuote } = quote
  const { keyUri, signature } = signatureFromJson(attesterSignature)
  await verifyDidSignature({
    signerUrl: keyUri,
    signature,
    message: Crypto.hashStr(Crypto.encodeObjectAsStr(basicQuote)),
    expectedSigner: basicQuote.attesterDid,
    expectedVerificationRelationship: 'authentication',
    // @ts-expect-error this is dumb
    dereferenceDidUrl,
  })

  const messages: string[] = []
  if (!validateQuoteSchema(QuoteSchema, basicQuote, messages)) {
    throw new QuoteError.QuoteUnverifiableError()
  }
}

/**
 * Creates a [[Quote]] signed by the Attester and the Claimer.
 *
 * @param attesterSignedQuote A [[Quote]] object signed by an Attester.
 * @param credentialRootHash A root hash of the entire object.
 * @param signer A signer interface handling signing with the Claimer's authentication key.
 * @param claimerDid The DID of the Claimer, who has to sign.
 * @param options Optional settings.
 * @param options.dereferenceDidUrl Resolve function used in the process of verifying the attester signature.
 * @returns A [[Quote]] agreement signed by both the Attester and Claimer.
 */
export async function createQuoteAgreement(
  attesterSignedQuote: IQuoteAttesterSigned,
  credentialRootHash: ICredential['rootHash'],
  signer: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>,
  claimerDid: Did,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<IQuoteAgreement> {
  const { attesterSignature, ...basicQuote } = attesterSignedQuote

  const transformed = signatureFromJson(attesterSignature)
  await verifyDidSignature({
    signature: transformed.signature,
    signerUrl: transformed.keyUri,
    message: Crypto.hashStr(Crypto.encodeObjectAsStr(basicQuote)),
    expectedVerificationRelationship: 'authentication',
    // @ts-expect-error why would this complain?
    dereferenceDidUrl,
  })

  const quoteAgreement = {
    ...attesterSignedQuote,
    rootHash: credentialRootHash,
    claimerDid,
  }
  const signature = await signer.sign({
    data: Crypto.hash(Crypto.encodeObjectAsStr(quoteAgreement)),
  })

  return {
    ...quoteAgreement,
    claimerSignature: { signature: Crypto.u8aToHex(signature), keyUri: signer.id },
  }
}

/**
 * Verifies a [[IQuoteAgreement]] object.
 *
 * @param quote The object to be verified.
 * @param options Optional settings.
 * @param options.dereferenceDidUrl Resolve function used in the process of verifying the attester signature.
 */
export async function verifyQuoteAgreement(
  quote: IQuoteAgreement,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<void> {
  const { claimerSignature, claimerDid, rootHash, ...attesterSignedQuote } = quote
  // verify attester signature
  await verifyAttesterSignedQuote(attesterSignedQuote, { dereferenceDidUrl })
  // verify claimer signature
  const { keyUri, signature } = signatureFromJson(claimerSignature)
  await verifyDidSignature({
    signature,
    signerUrl: keyUri,
    message: Crypto.hashStr(Crypto.encodeObjectAsStr({ ...attesterSignedQuote, claimerDid, rootHash })),
    expectedSigner: claimerDid,
    expectedVerificationRelationship: 'authentication',
    // @ts-expect-error why would this complain?
    dereferenceDidUrl,
  })
}
