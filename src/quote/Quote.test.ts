/**
 * Copyright (c) 2025, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { CType } from '@kiltprotocol/credentials'
import * as DidModule from '@kiltprotocol/did'
import { Credential } from '@kiltprotocol/legacy-credentials'
import type { DidDocument, ICType, IClaim, ICredential } from '@kiltprotocol/types'
import { Crypto } from '@kiltprotocol/utils'
import { blake2AsU8a } from '@polkadot/util-crypto'
import { u8aToHex } from '@polkadot/util'
import { createLocalDemoFullDidFromKeypair, makeMockDereference, makeSigningKeyTool } from '../tests'
import { ICostBreakdown, IQuote, IQuoteAgreement, IQuoteIssuerSigned } from '../types'
import * as Quote from './Quote'
import { QuoteSchema } from './QuoteSchema'

describe('Quote', () => {
  let holderIdentity: DidDocument
  const holder = makeSigningKeyTool('ed25519')

  let issuerIdentity: DidDocument
  const issuer = makeSigningKeyTool('ed25519')

  let invalidCost: ICostBreakdown
  let date: string
  let testCType: ICType
  let claim: IClaim
  let credential: ICredential
  let invalidCostQuoteData: IQuote
  let invalidPropertiesQuoteData: IQuote
  let validQuoteData: IQuote
  let validIssuerSignedQuote: IQuoteIssuerSigned
  let quoteBothAgreed: IQuoteAgreement
  let invalidPropertiesQuote: IQuote
  let invalidCostQuote: IQuote
  let dereferenceDidUrl: ReturnType<typeof makeMockDereference>

  beforeAll(async () => {
    holderIdentity = await createLocalDemoFullDidFromKeypair((await holder).keypair)

    issuerIdentity = await createLocalDemoFullDidFromKeypair((await issuer).keypair)

    dereferenceDidUrl = makeMockDereference([holderIdentity, issuerIdentity])

    invalidCost = {
      gross: 233,
      tax: { vat: 3.3 },
    } as unknown as ICostBreakdown
    date = new Date(2019, 11, 10).toISOString()

    testCType = CType.fromProperties('Quote Information', {
      name: { type: 'string' },
    })

    claim = {
      cTypeHash: CType.idToHash(testCType.$id),
      contents: {},
      owner: holderIdentity.id,
    }

    // build credential with legitimations
    credential = Credential.fromClaim(claim)

    // Initialize the variable with proper type
    invalidCostQuoteData = {
      issuerDid: issuerIdentity.id,
      cTypeHash: '0x12345678',
      cost: invalidCost,
      currency: 'Euro',
      timeframe: date,
      termsAndConditions: 'Lots of these',
    }

    invalidPropertiesQuoteData = {
      cTypeHash: '0x12345678',
      cost: {
        gross: 233,
        net: 23.3,
        tax: { vat: 3.3 },
      },
      timeframe: date,
      currency: 'Euro',
      termsAndConditions: 'Lots of these',
    } as unknown as IQuote

    validQuoteData = {
      issuerDid: issuerIdentity.id,
      cTypeHash: '0x12345678',
      cost: {
        gross: 233,
        net: 23.3,
        tax: { vat: 3.3 },
      },
      currency: 'Euro',
      timeframe: new Date('12-04-2020').toISOString(),
      termsAndConditions: 'Lots of these',
    }
    validIssuerSignedQuote = await Quote.createIssuerSignedQuote(
      validQuoteData,
      (await (await issuer).getSigners<'Sr25519'>(issuerIdentity, { verificationRelationship: 'authentication' }))[0]
    )
    quoteBothAgreed = await Quote.createQuoteAgreement(
      validIssuerSignedQuote,
      credential.rootHash,
      (await (await holder).getSigners<'Sr25519'>(holderIdentity, { verificationRelationship: 'authentication' }))[0],
      holderIdentity.id,
      {
        dereferenceDidUrl,
      }
    )
    invalidPropertiesQuote = invalidPropertiesQuoteData
    invalidCostQuote = invalidCostQuoteData
  })

  it('tests created quote data against given data', async () => {
    expect(validQuoteData.issuerDid).toEqual(issuerIdentity.id)
    const signer = (await (await holder).getSigners(holderIdentity, { verificationRelationship: 'authentication' }))[0]
    const sig = await signer.sign({
      data: blake2AsU8a(
        Crypto.encodeObjectAsStr({
          ...validIssuerSignedQuote,
          holderDid: holderIdentity.id,
          rootHash: credential.rootHash,
        })
      ),
    })

    const signature = {
      signature: u8aToHex(sig),
      keyUri: signer.id,
    }
    expect(signature).toEqual(quoteBothAgreed.claimerSignature)

    // const { fragment: issuerKeyId } = DidModule.parse(validIssuerSignedQuote.issuerSignature.keyUri)
    const issuerKey = issuerIdentity.verificationMethod?.find(
      ({ id }) => id === validIssuerSignedQuote.issuerSignature.keyUri
    )
    if (!issuerKey) {
      throw new Error('Issuer key not found')
    }

    expect(() =>
      Crypto.verify(
        Crypto.hashStr(
          Crypto.encodeObjectAsStr({
            issuerDid: validQuoteData.issuerDid,
            cTypeHash: validQuoteData.cTypeHash,
            cost: validQuoteData.cost,
            currency: validQuoteData.currency,
            timeframe: validQuoteData.timeframe,
            termsAndConditions: validQuoteData.termsAndConditions,
          })
        ),
        validIssuerSignedQuote.issuerSignature.signature,
        DidModule.multibaseKeyToDidKey(issuerKey.publicKeyMultibase).publicKey
      )
    ).not.toThrow()
    await expect(
      Quote.verifyIssuerSignedQuote(validIssuerSignedQuote, {
        dereferenceDidUrl,
      })
    ).resolves.not.toThrow()
    await expect(
      Quote.verifyQuoteAgreement(quoteBothAgreed, {
        dereferenceDidUrl,
      })
    ).resolves.not.toThrow()
    await expect(
      Quote.createIssuerSignedQuote(
        validQuoteData,
        (await (await issuer).getSigners<'Sr25519'>(issuerIdentity, { verificationRelationship: 'authentication' }))[0]
      )
    ).resolves.toEqual(validIssuerSignedQuote)
  })
  it('validates created quotes against QuoteSchema', () => {
    expect(Quote.validateQuoteSchema(QuoteSchema, validQuoteData)).toBe(true)
    expect(Quote.validateQuoteSchema(QuoteSchema, invalidCostQuote)).toBe(false)
    expect(Quote.validateQuoteSchema(QuoteSchema, invalidPropertiesQuote)).toBe(false)
  })

  it('detects tampering', async () => {
    const messedWithCurrency: IQuoteIssuerSigned = {
      ...validIssuerSignedQuote,
      currency: 'Bananas',
    }
    await expect(
      Quote.verifyIssuerSignedQuote(messedWithCurrency, {
        dereferenceDidUrl,
      })
    ).rejects.toThrow()
    const messedWithRootHash: IQuoteAgreement = {
      ...quoteBothAgreed,
      rootHash: '0x1234',
    }
    await expect(
      Quote.verifyQuoteAgreement(messedWithRootHash, {
        dereferenceDidUrl,
      })
    ).rejects.toThrow()
  })

  it('complains if issuerDid does not match issuer signature', async () => {
    const signer = (await (await holder).getSigners(holderIdentity, { verificationRelationship: 'authentication' }))[0]
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { issuerSignature, ...issuerSignedQuote } = validIssuerSignedQuote
    const wrongSignerIssuer: IQuoteIssuerSigned = {
      ...issuerSignedQuote,
      issuerSignature: {
        signature: (
          await signer.sign({
            data: Crypto.hash(Crypto.encodeObjectAsStr(issuerSignedQuote)),
          })
        ).toString(),
        keyUri: signer.id,
      },
    }

    await expect(
      Quote.verifyIssuerSignedQuote(wrongSignerIssuer, {
        dereferenceDidUrl,
      })
    ).rejects.toThrow()
  })

  it('complains if holderDid does not match holder signature', async () => {
    const signer = (await (await issuer).getSigners(issuerIdentity, { verificationRelationship: 'authentication' }))[0]
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { claimerSignature, ...restQuote } = quoteBothAgreed
    const wrongSignerHolder: IQuoteAgreement = {
      ...restQuote,
      claimerSignature: {
        signature: (
          await signer.sign({
            data: Crypto.hash(Crypto.encodeObjectAsStr(restQuote)),
          })
        ).toString(),
        keyUri: signer.id,
      },
    }

    await expect(
      Quote.verifyQuoteAgreement(wrongSignerHolder, {
        dereferenceDidUrl,
      })
    ).rejects.toThrow()
  })
})
