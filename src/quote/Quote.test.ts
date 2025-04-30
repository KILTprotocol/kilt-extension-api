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
import { ICostBreakdown, IQuote, IQuoteAgreement, IQuoteAttesterSigned } from '../types'
import * as Quote from './Quote'
import { QuoteSchema } from './QuoteSchema'

describe('Quote', () => {
  let claimerIdentity: DidDocument
  const claimer = makeSigningKeyTool('ed25519')

  let attesterIdentity: DidDocument
  const attester = makeSigningKeyTool('ed25519')

  let invalidCost: ICostBreakdown
  let date: string
  let testCType: ICType
  let claim: IClaim
  let credential: ICredential
  let invalidCostQuoteData: IQuote
  let invalidPropertiesQuoteData: IQuote
  let validQuoteData: IQuote
  let validAttesterSignedQuote: IQuoteAttesterSigned
  let quoteBothAgreed: IQuoteAgreement
  let invalidPropertiesQuote: IQuote
  let invalidCostQuote: IQuote
  let dereferenceDidUrl: ReturnType<typeof makeMockDereference>

  beforeAll(async () => {
    claimerIdentity = await createLocalDemoFullDidFromKeypair((await claimer).keypair)

    attesterIdentity = await createLocalDemoFullDidFromKeypair((await attester).keypair)

    dereferenceDidUrl = makeMockDereference([claimerIdentity, attesterIdentity])

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
      owner: claimerIdentity.id,
    }

    // build credential with legitimations
    credential = Credential.fromClaim(claim)

    // Initialize the variable with proper type
    invalidCostQuoteData = {
      attesterDid: attesterIdentity.id,
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
      attesterDid: attesterIdentity.id,
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
    validAttesterSignedQuote = await Quote.createAttesterSignedQuote(
      validQuoteData,
      (
        await (await attester).getSigners<'Sr25519'>(attesterIdentity, { verificationRelationship: 'authentication' })
      )[0]
    )
    quoteBothAgreed = await Quote.createQuoteAgreement(
      validAttesterSignedQuote,
      credential.rootHash,
      (await (await claimer).getSigners<'Sr25519'>(claimerIdentity, { verificationRelationship: 'authentication' }))[0],
      claimerIdentity.id,
      {
        dereferenceDidUrl,
      }
    )
    invalidPropertiesQuote = invalidPropertiesQuoteData
    invalidCostQuote = invalidCostQuoteData
  })

  it('tests created quote data against given data', async () => {
    expect(validQuoteData.attesterDid).toEqual(attesterIdentity.id)
    const signer = (
      await (await claimer).getSigners(claimerIdentity, { verificationRelationship: 'authentication' })
    )[0]
    const sig = await signer.sign({
      data: blake2AsU8a(
        Crypto.encodeObjectAsStr({
          ...validAttesterSignedQuote,
          claimerDid: claimerIdentity.id,
          rootHash: credential.rootHash,
        })
      ),
    })

    const signature = {
      signature: u8aToHex(sig),
      keyUri: signer.id,
    }
    expect(signature).toEqual(quoteBothAgreed.claimerSignature)

    // const { fragment: attesterKeyId } = DidModule.parse(validAttesterSignedQuote.attesterSignature.keyUri)
    const attesterKey = attesterIdentity.verificationMethod?.find(
      ({ id }) => id === validAttesterSignedQuote.attesterSignature.keyUri
    )
    if (!attesterKey) {
      throw new Error('Attester key not found')
    }

    expect(() =>
      Crypto.verify(
        Crypto.hashStr(
          Crypto.encodeObjectAsStr({
            attesterDid: validQuoteData.attesterDid,
            cTypeHash: validQuoteData.cTypeHash,
            cost: validQuoteData.cost,
            currency: validQuoteData.currency,
            timeframe: validQuoteData.timeframe,
            termsAndConditions: validQuoteData.termsAndConditions,
          })
        ),
        validAttesterSignedQuote.attesterSignature.signature,
        DidModule.multibaseKeyToDidKey(attesterKey.publicKeyMultibase).publicKey
      )
    ).not.toThrow()
    await expect(
      Quote.verifyAttesterSignedQuote(validAttesterSignedQuote, {
        dereferenceDidUrl,
      })
    ).resolves.not.toThrow()
    await expect(
      Quote.verifyQuoteAgreement(quoteBothAgreed, {
        dereferenceDidUrl,
      })
    ).resolves.not.toThrow()
    await expect(
      Quote.createAttesterSignedQuote(
        validQuoteData,
        (
          await (await attester).getSigners<'Sr25519'>(attesterIdentity, { verificationRelationship: 'authentication' })
        )[0]
      )
    ).resolves.toEqual(validAttesterSignedQuote)
  })
  it('validates created quotes against QuoteSchema', () => {
    expect(Quote.validateQuoteSchema(QuoteSchema, validQuoteData)).toBe(true)
    expect(Quote.validateQuoteSchema(QuoteSchema, invalidCostQuote)).toBe(false)
    expect(Quote.validateQuoteSchema(QuoteSchema, invalidPropertiesQuote)).toBe(false)
  })

  it('detects tampering', async () => {
    const messedWithCurrency: IQuoteAttesterSigned = {
      ...validAttesterSignedQuote,
      currency: 'Bananas',
    }
    await expect(
      Quote.verifyAttesterSignedQuote(messedWithCurrency, {
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

  it('complains if attesterDid does not match attester signature', async () => {
    const signer = (
      await (await claimer).getSigners(claimerIdentity, { verificationRelationship: 'authentication' })
    )[0]
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { attesterSignature, ...attesterSignedQuote } = validAttesterSignedQuote
    const wrongSignerAttester: IQuoteAttesterSigned = {
      ...attesterSignedQuote,
      attesterSignature: {
        signature: (
          await signer.sign({
            data: Crypto.hash(Crypto.encodeObjectAsStr(attesterSignedQuote)),
          })
        ).toString(),
        keyUri: signer.id,
      },
    }

    await expect(
      Quote.verifyAttesterSignedQuote(wrongSignerAttester, {
        dereferenceDidUrl,
      })
    ).rejects.toThrow()
  })

  it('complains if claimerDid does not match claimer signature', async () => {
    const signer = (
      await (await attester).getSigners(attesterIdentity, { verificationRelationship: 'authentication' })
    )[0]
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { claimerSignature, ...restQuote } = quoteBothAgreed
    const wrongSignerClaimer: IQuoteAgreement = {
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
      Quote.verifyQuoteAgreement(wrongSignerClaimer, {
        dereferenceDidUrl,
      })
    ).rejects.toThrow()
  })
})
