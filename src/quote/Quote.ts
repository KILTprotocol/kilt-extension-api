/**
 * Copyright (c) 2025, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/**
 * [[Quote]] constructs a framework for Issuers to make an offer for building a [[Claim]] on a [[CType]] in which it includes a price and other terms & conditions upon which a holder can agree.
 *
 * A [[Quote]] object represents a legal **offer** for the closure of a contract attesting a [[Claim]] from the [[CType]] specified within the offer.
 *
 * A [[Quote]] comes with a versionable spec, allowing different [[Quote]] specs to exist over time and tracks under which [[Quote]] a contract was closed.
 *
 * @packageDocumentation
 */

import { dereference, resolve, signatureFromJson, verifyDidSignature } from '@kiltprotocol/did'
import type {
  Did,
  DidDocument,
  DidUrl,
  ICredential,
  ResolutionMetadata,
  ResolutionOptions,
  SignerInterface,
} from '@kiltprotocol/types'
import { Crypto, JsonSchema, Signers } from '@kiltprotocol/utils'
import { IQuote, IQuoteAgreement, IQuoteIssuerSigned } from '../types/Quote.js'
import * as QuoteError from './Error.js'
import { QuoteSchema } from './QuoteSchema.js'

export function dereferenceToResolve(dereferenceImplementation?: typeof dereference): typeof resolve | undefined {
  if (typeof dereferenceImplementation !== 'function') {
    return dereferenceImplementation
  }
  return async (did: Did, resolutionOptions?: ResolutionOptions | undefined) => {
    const { dereferencingMetadata, contentMetadata, contentStream } = await dereferenceImplementation(did, {
      ...resolutionOptions,
      accept: 'application/did+json',
    })
    return {
      didResolutionMetadata: dereferencingMetadata as ResolutionMetadata,
      didDocument: contentStream as DidDocument | undefined,
      didDocumentMetadata: contentMetadata,
    }
  }
}
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
 * Signs a [[Quote]] object as an Issuer.
 *
 * @param quoteInput A [[Quote]] object.
 * @param signer A signer interface handling signing with the issue's authentication key.
 * @returns A signed [[Quote]] object.
 */
export async function createIssuerSignedQuote(
  quoteInput: IQuote,
  signer: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>
): Promise<IQuoteIssuerSigned> {
  if (!validateQuoteSchema(QuoteSchema, quoteInput)) {
    throw new QuoteError.QuoteUnverifiableError()
  }

  const signature = await signer.sign({
    data: Crypto.hash(Crypto.encodeObjectAsStr(quoteInput)),
  })
  return {
    ...quoteInput,
    issuerSignature: { signature: Crypto.u8aToHex(signature), keyUri: signer.id },
  }
}

/**
 * Verifies a [[IQuoteIssuerSigned]] object.
 *
 * @param quote The object which to be verified.
 * @param options Optional settings.
 * @param options.dereferenceDidUrl Resolve function used in the process of verifying the issuer signature.
 */
export async function verifyIssuerSignedQuote(
  quote: IQuoteIssuerSigned,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<void> {
  const { issuerSignature, ...basicQuote } = quote
  const { signerUrl, signature } = signatureFromJson(issuerSignature)
  await verifyDidSignature({
    signerUrl,
    signature,
    message: Crypto.hashStr(Crypto.encodeObjectAsStr(basicQuote)),
    expectedSigner: basicQuote.issuerDid,
    expectedVerificationRelationship: 'authentication',
    didResolver: dereferenceToResolve(dereferenceDidUrl),
  })

  const messages: string[] = []
  if (!validateQuoteSchema(QuoteSchema, basicQuote, messages)) {
    throw new QuoteError.QuoteUnverifiableError()
  }
}

/**
 * Creates a [[Quote]] signed by the Issuer and the Holder.
 *
 * @param issuerSignedQuote A [[Quote]] object signed by an Issuer.
 * @param credentialRootHash A root hash of the entire object.
 * @param signer A signer interface handling signing with the Holder's authentication key.
 * @param holderDid The DID of the Holder, who has to sign.
 * @param options Optional settings.
 * @param options.dereferenceDidUrl Resolve function used in the process of verifying the issuer signature.
 * @returns A [[Quote]] agreement signed by both the Issuer and Holder.
 */
export async function createQuoteAgreement(
  issuerSignedQuote: IQuoteIssuerSigned,
  credentialRootHash: ICredential['rootHash'],
  signer: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>,
  holderDid: Did,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<IQuoteAgreement> {
  const { issuerSignature, ...basicQuote } = issuerSignedQuote

  const transformed = signatureFromJson(issuerSignature)
  await verifyDidSignature({
    signature: transformed.signature,
    signerUrl: transformed.signerUrl,
    message: Crypto.hashStr(Crypto.encodeObjectAsStr(basicQuote)),
    expectedVerificationRelationship: 'authentication',
    didResolver: dereferenceToResolve(dereferenceDidUrl),
  })

  const quoteAgreement = {
    ...issuerSignedQuote,
    rootHash: credentialRootHash,
    holderDid,
  }
  const signature = await signer.sign({
    data: Crypto.hash(Crypto.encodeObjectAsStr(quoteAgreement)),
  })

  return {
    ...quoteAgreement,
    holderSignature: { signature: Crypto.u8aToHex(signature), keyUri: signer.id },
  }
}

/**
 * Verifies a [[IQuoteAgreement]] object.
 *
 * @param quote The object to be verified.
 * @param options Optional settings.
 * @param options.dereferenceDidUrl Resolve function used in the process of verifying the issuer signature.
 */
export async function verifyQuoteAgreement(
  quote: IQuoteAgreement,
  {
    dereferenceDidUrl,
  }: {
    dereferenceDidUrl?: typeof dereference
  } = {}
): Promise<void> {
  const { holderSignature, holderDid, rootHash, ...issuerSignedQuote } = quote
  // verify issuer signature
  await verifyIssuerSignedQuote(issuerSignedQuote, { dereferenceDidUrl })
  // verify holder signature
  const { signerUrl, signature } = signatureFromJson(holderSignature)
  await verifyDidSignature({
    signature,
    signerUrl: signerUrl,
    message: Crypto.hashStr(Crypto.encodeObjectAsStr({ ...issuerSignedQuote, holderDid, rootHash })),
    expectedSigner: holderDid,
    expectedVerificationRelationship: 'authentication',
    didResolver: dereferenceToResolve(dereferenceDidUrl),
  })
}
