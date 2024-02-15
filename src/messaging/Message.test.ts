/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/* eslint-disable @typescript-eslint/ban-ts-comment */

/**
 * Copyright (c) 2018-2024, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { u8aToHex } from '@polkadot/util'
import { Attestation, CType, Claim, Credential, Quote } from '@kiltprotocol/core'
import * as Did from '@kiltprotocol/did'
import { init } from '@kiltprotocol/sdk-js'
import * as MessageError from './Error'
import { Crypto } from '@kiltprotocol/utils'
import type {
  DidDocument,
  DidKey,
  DidResourceUri,
  DidUri,
  IAttestation,
  ICType,
  ResolvedDidKey,
  IClaim,
  ICredential,
  ICredentialPresentation,
} from '@kiltprotocol/sdk-js'

import {
  KeyTool,
  KeyToolSignCallback,
  createLocalDemoFullDidFromKeypair,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeSigningKeyTool,
} from '../tests'
import { fromBody, verifyRequiredCTypeProperties } from './utils'
import { decrypt, encrypt, verifyMessageEnvelope } from './MessageEnvelope'
import { ensureOwnerIsSender, assertKnownMessage, assertKnownMessageBody } from './CredentialApiMessageType'
import type {
  IEncryptedMessage,
  IMessage,
  IQuote,
  IQuoteAgreement,
  IQuoteAttesterSigned,
  IRejectAttestation,
  IRequestAttestation,
  IRequestAttestationContent,
  IRequestCredential,
  IRequestCredentialContent,
  ISubmitAttestation,
  ISubmitAttestationContent,
  ISubmitCredential,
  ISubmitTerms,
  ITerms,
} from '../types'

describe('Messaging', () => {
  let aliceLightDid: DidDocument
  let aliceLightDidWithDetails: DidDocument
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSignCallback
  const aliceEncKey = makeEncryptionKeyTool('Alice//enc')

  let bobLightDid: DidDocument
  let bobLightDidWithDetails: DidDocument
  let bobFullDid: DidDocument
  let bobSign: KeyToolSignCallback
  const bobEncKey = makeEncryptionKeyTool('Bob//enc')

  async function resolveKey(keyUri: DidResourceUri, keyRelationship = 'authentication'): Promise<ResolvedDidKey> {
    const { did } = Did.parse(keyUri)
    const document = [
      aliceLightDidWithDetails,
      aliceLightDid,
      aliceFullDid,
      bobLightDidWithDetails,
      bobLightDid,
      bobFullDid,
    ].find(({ uri }) => uri === did)
    if (!document) throw new Error('Cannot resolve mocked DID')
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return Did.keyToResolvedKey(document[keyRelationship as keyof DidDocument]![0] as DidKey, did)
  }

  beforeAll(async () => {
    await init()
    const aliceAuthKey = makeSigningKeyTool('ed25519')
    aliceSign = aliceAuthKey.getSignCallback
    aliceLightDid = Did.createLightDidDocument({
      authentication: aliceAuthKey.authentication,
      keyAgreement: aliceEncKey.keyAgreement,
    })
    aliceLightDidWithDetails = Did.createLightDidDocument({
      authentication: aliceAuthKey.authentication,
      keyAgreement: aliceEncKey.keyAgreement,
      service: [{ id: '#id-1', type: ['type-1'], serviceEndpoint: ['x:url-1'] }],
    })
    aliceFullDid = await createLocalDemoFullDidFromLightDid(aliceLightDid)

    const bobAuthKey = makeSigningKeyTool('ed25519')
    bobSign = bobAuthKey.getSignCallback
    bobLightDid = Did.createLightDidDocument({
      authentication: bobAuthKey.authentication,
      keyAgreement: bobEncKey.keyAgreement,
    })
    bobLightDidWithDetails = Did.createLightDidDocument({
      authentication: bobAuthKey.authentication,
      keyAgreement: bobEncKey.keyAgreement,
      service: [{ id: '#id-1', type: ['type-1'], serviceEndpoint: ['x:url-1'] }],
    })
    bobFullDid = await createLocalDemoFullDidFromLightDid(bobLightDid)
  })

  it('verify message encryption and signing', async () => {
    const message = fromBody(
      {
        type: 'request-credential',
        content: {
          cTypes: [{ cTypeHash: `${Crypto.hashStr('0x12345678')}` }],
        },
      },
      aliceLightDid.uri,
      bobLightDid.uri
    )
    const encryptedMessage = await encrypt(
      message,
      aliceEncKey.encrypt(aliceLightDid),
      `${bobLightDid.uri}#encryption`,
      { resolveKey }
    )

    const decryptedMessage = await decrypt(encryptedMessage, bobEncKey.decrypt, { resolveKey })
    expect(JSON.stringify(message.body)).toEqual(JSON.stringify(decryptedMessage.body))

    expect(() => assertKnownMessage(decryptedMessage)).not.toThrow()

    const encryptedMessageWrongContent = JSON.parse(
      JSON.stringify(encryptedMessage)
    ) as IEncryptedMessage<IRequestCredential>
    const messedUpContent = Crypto.coToUInt8(encryptedMessageWrongContent.ciphertext)
    messedUpContent.set(Crypto.hash('1234'), 10)
    encryptedMessageWrongContent.ciphertext = u8aToHex(messedUpContent)

    await expect(() =>
      decrypt(encryptedMessageWrongContent, bobEncKey.decrypt, {
        resolveKey,
      })
    ).rejects.toThrowError(MessageError.DecodingMessageError)

    const encryptedWrongBody = await aliceEncKey.encrypt(aliceLightDid)({
      data: Crypto.coToUInt8('{ wrong JSON'),
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      peerPublicKey: bobLightDid.keyAgreement![0].publicKey,
      did: aliceLightDid.uri,
    })
    const encryptedMessageWrongBody: IEncryptedMessage<IRequestCredential> = {
      ciphertext: u8aToHex(encryptedWrongBody.data),
      nonce: u8aToHex(encryptedWrongBody.nonce),
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      senderKeyUri: `${aliceLightDid.uri}${aliceLightDid.keyAgreement![0].id}`,
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      receiverKeyUri: `${bobLightDid.uri}${bobLightDid.keyAgreement![0].id}`,
    }
    await expect(() =>
      decrypt(encryptedMessageWrongBody, bobEncKey.decrypt, {
        resolveKey,
      })
    ).rejects.toThrowError(SyntaxError)
  })

  it('verifies the message with sender is the owner (as full DID)', async () => {
    const credential = Credential.fromClaim({
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      owner: aliceFullDid.uri,
      contents: {},
    })

    const presentation = await Credential.createPresentation({
      credential,
      signCallback: aliceSign(aliceFullDid),
    })

    const date = new Date(2019, 11, 10).toISOString()

    const quoteData: IQuote = {
      attesterDid: bobFullDid.uri,
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: date,
    }
    const quoteAttesterSigned = await Quote.createAttesterSignedQuote(quoteData, bobSign(bobFullDid))
    const bothSigned = await Quote.createQuoteAgreement(
      quoteAttesterSigned,
      credential.rootHash,
      aliceSign(aliceFullDid),
      aliceFullDid.uri,
      { didResolveKey: resolveKey }
    )
    const requestAttestationBody: IRequestAttestation = {
      content: {
        credential,
        quote: bothSigned,
      },
      type: 'request-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceFullDid.uri, bobFullDid.uri))).not.toThrow()

    // Should not throw if the sender is the light DID version of the owner.
    // This is technically not to be allowed but message verification is not concerned with that.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceLightDid.uri, bobFullDid.uri))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, bobFullDid.uri, aliceFullDid.uri))).toThrowError(
      MessageError.IdentityMismatchError
    )

    const attestation = {
      delegationId: null,
      claimHash: requestAttestationBody.content.credential.rootHash,
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobFullDid.uri,
      revoked: false,
    }

    const submitAttestationBody: ISubmitAttestation = {
      content: {
        attestation,
      },
      type: 'submit-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobFullDid.uri, aliceFullDid.uri))).not.toThrow()

    // Should not throw if the sender is the light DID version of the owner.
    // This is technically not to be allowed but message verification is not concerned with that.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobLightDid.uri, aliceFullDid.uri))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, aliceFullDid.uri, bobFullDid.uri))).toThrowError(
      MessageError.IdentityMismatchError
    )

    const submitClaimsForCTypeBody: ISubmitCredential = {
      content: [presentation],
      type: 'submit-credential',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceFullDid.uri, bobFullDid.uri))
    ).not.toThrow()

    // Should not throw if the sender is the light DID version of the owner.
    // This is technically not to be allowed but message verification is not concerned with that.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceLightDid.uri, bobFullDid.uri))
    ).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, bobFullDid.uri, aliceFullDid.uri))
    ).toThrowError(MessageError.IdentityMismatchError)
  })

  it('verifies the message with sender is the owner (as light DID)', async () => {
    // Create request for attestation to the light DID with no encoded details
    const credential = Credential.fromClaim({
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      owner: aliceLightDid.uri,
      contents: {},
    })

    const presentation = await Credential.createPresentation({
      credential,
      signCallback: aliceSign(aliceLightDid),
    })

    const date = new Date(2019, 11, 10).toISOString()
    const quoteData: IQuote = {
      attesterDid: bobLightDid.uri,
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: date,
    }
    const quoteAttesterSigned = await Quote.createAttesterSignedQuote(quoteData, bobSign(bobLightDid))
    const bothSigned = await Quote.createQuoteAgreement(
      quoteAttesterSigned,
      credential.rootHash,
      aliceSign(aliceLightDid),
      aliceLightDid.uri,
      { didResolveKey: resolveKey }
    )
    const requestAttestationBody: IRequestAttestation = {
      content: {
        credential,
        quote: bothSigned,
      },
      type: 'request-attestation',
    }

    // Create request for attestation to the light DID with encoded details
    const contentWithEncodedDetails = await Credential.createPresentation({
      credential: Credential.fromClaim({
        cTypeHash: `${Crypto.hashStr('0x12345678')}`,
        owner: aliceLightDidWithDetails.uri,
        contents: {},
      }),
      signCallback: aliceSign(aliceLightDidWithDetails),
    })

    const quoteDataEncodedDetails: IQuote = {
      attesterDid: bobLightDidWithDetails.uri,
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: date,
    }
    const quoteAttesterSignedEncodedDetails = await Quote.createAttesterSignedQuote(
      quoteDataEncodedDetails,
      bobSign(bobLightDidWithDetails)
    )
    const bothSignedEncodedDetails = await Quote.createQuoteAgreement(
      quoteAttesterSignedEncodedDetails,
      credential.rootHash,
      aliceSign(aliceLightDidWithDetails),
      aliceLightDidWithDetails.uri,
      { didResolveKey: resolveKey }
    )
    const requestAttestationBodyWithEncodedDetails: IRequestAttestation = {
      content: {
        credential: contentWithEncodedDetails,
        quote: bothSignedEncodedDetails,
      },
      type: 'request-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() =>
      ensureOwnerIsSender(fromBody(requestAttestationBody, aliceLightDid.uri, bobLightDid.uri))
    ).not.toThrow()

    // Should not throw if the owner has no additional details and the sender does.
    expect(() =>
      ensureOwnerIsSender(
        fromBody(requestAttestationBodyWithEncodedDetails, aliceLightDidWithDetails.uri, bobLightDid.uri)
      )
    ).not.toThrow()

    // Should not throw if the owner has additional details and the sender does not.
    expect(() =>
      ensureOwnerIsSender(fromBody(requestAttestationBodyWithEncodedDetails, aliceLightDid.uri, bobLightDid.uri))
    ).not.toThrow()

    // Should not throw if the sender is the full DID version of the owner.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceFullDid.uri, bobLightDid.uri))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() =>
      ensureOwnerIsSender(fromBody(requestAttestationBody, bobLightDid.uri, aliceLightDid.uri))
    ).toThrowError(MessageError.IdentityMismatchError)

    const attestation = {
      delegationId: null,
      claimHash: requestAttestationBody.content.credential.rootHash,
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobLightDid.uri,
      revoked: false,
    }

    const submitAttestationBody: ISubmitAttestation = {
      content: {
        attestation,
      },
      type: 'submit-attestation',
    }

    const attestationWithEncodedDetails = {
      delegationId: null,
      claimHash: requestAttestationBody.content.credential.rootHash,
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobLightDidWithDetails.uri,
      revoked: false,
    }

    const submitAttestationBodyWithEncodedDetails: ISubmitAttestation = {
      content: {
        attestation: attestationWithEncodedDetails,
      },
      type: 'submit-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobLightDid.uri, aliceLightDid.uri))).not.toThrow()

    // Should not throw if the owner has no additional details and the sender does.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitAttestationBody, bobLightDidWithDetails.uri, aliceLightDid.uri))
    ).not.toThrow()

    // Should not throw if the owner has additional details and the sender does not.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitAttestationBodyWithEncodedDetails, bobLightDid.uri, aliceLightDid.uri))
    ).not.toThrow()

    // Should not throw if the sender is the full DID version of the owner.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobFullDid.uri, aliceLightDid.uri))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, aliceLightDid.uri, bobLightDid.uri))).toThrowError(
      MessageError.IdentityMismatchError
    )

    const submitClaimsForCTypeBody: ISubmitCredential = {
      content: [presentation],
      type: 'submit-credential',
    }

    const submitClaimsForCTypeBodyWithEncodedDetails: ISubmitCredential = {
      content: [contentWithEncodedDetails],
      type: 'submit-credential',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceLightDid.uri, bobLightDid.uri))
    ).not.toThrow()

    // Should not throw if the owner has no additional details and the sender does.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceLightDidWithDetails.uri, bobLightDid.uri))
    ).not.toThrow()

    // Should not throw if the owner has additional details and the sender does not.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBodyWithEncodedDetails, aliceLightDid.uri, bobLightDid.uri))
    ).not.toThrow()

    // Should not throw if the sender is the full DID version of the owner.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceFullDid.uri, bobLightDid.uri))
    ).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, bobLightDid.uri, aliceLightDid.uri))
    ).toThrowError(MessageError.IdentityMismatchError)
  })
})

describe('Error checking / Verification', () => {
  // TODO: Duplicated code, would be nice to have as a seperated test package with similar helpers
  async function buildCredential(
    claimerDid: DidUri,
    attesterDid: DidUri,
    contents: IClaim['contents'],
    legitimations: ICredential[]
  ): Promise<[ICredential, IAttestation]> {
    // create claim

    const testCType = CType.fromProperties('Credential', {
      name: { type: 'string' },
    })

    const claim = Claim.fromCTypeAndClaimContents(testCType, contents, claimerDid)
    // build credential with legitimations
    const credential = Credential.fromClaim(claim, {
      legitimations,
    })
    // build attestation
    const testAttestation = Attestation.fromCredentialAndDid(credential, attesterDid)
    return [credential, testAttestation]
  }

  let identityAlice: DidDocument
  let keyAlice: KeyTool

  let identityBob: DidDocument
  let keyBob: KeyTool

  let date: string
  let testCType: ICType
  let testCTypeWithMultipleProperties: ICType
  let claim: IClaim
  let claimContents: IClaim['contents']
  let quoteData: IQuote
  let quoteAttesterSigned: IQuoteAttesterSigned
  let bothSigned: IQuoteAgreement
  let legitimation: ICredential
  let submitTermsBody: ISubmitTerms
  let submitTermsContent: ITerms
  let requestAttestationBody: IRequestAttestation
  let requestAttestationContent: IRequestAttestationContent
  let submitAttestationContent: ISubmitAttestationContent
  let submitAttestationBody: ISubmitAttestation
  let rejectAttestationForClaimBody: IRejectAttestation
  let requestCredentialBody: IRequestCredential
  let requestCredentialContent: IRequestCredentialContent
  let submitCredentialBody: ISubmitCredential
  let submitCredentialContent: ICredentialPresentation[]

  let messageSubmitTerms: IMessage
  let messageRequestAttestationForClaim: IMessage
  let messageSubmitAttestationForClaim: IMessage
  let messageRequestCredential: IMessage
  let messageRejectAttestationForClaim: IMessage
  let messageSubmitCredential: IMessage

  beforeAll(async () => {
    await init()

    keyAlice = makeSigningKeyTool()
    identityAlice = await createLocalDemoFullDidFromKeypair(keyAlice.keypair)
    keyBob = makeSigningKeyTool()
    identityBob = await createLocalDemoFullDidFromKeypair(keyBob.keypair)

    date = new Date(2019, 11, 10).toISOString()
    claimContents = {
      name: 'Bob',
    }

    async function didResolveKey(keyUri: DidResourceUri): Promise<ResolvedDidKey> {
      const { did } = Did.parse(keyUri)
      const document = [identityAlice, identityBob].find(({ uri }) => uri === did)
      if (!document) throw new Error('Cannot resolve mocked DID')
      return Did.keyToResolvedKey(document.authentication[0], did)
    }

    // CType
    testCType = CType.fromProperties('ClaimCtype', {
      name: { type: 'string' },
    })
    testCTypeWithMultipleProperties = CType.fromProperties('Drivers license Claim', {
      name: { type: 'string' },
      id: { type: 'string' },
      age: { type: 'string' },
    })

    // Claim
    claim = Claim.fromCTypeAndClaimContents(testCType, claimContents, identityAlice.uri)
    // Legitimation
    ;[legitimation] = await buildCredential(identityAlice.uri, identityBob.uri, {}, [])
    // Quote Data
    quoteData = {
      attesterDid: identityAlice.uri,
      cTypeHash: claim.cTypeHash,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: date,
    }
    // Quote signed by attester
    quoteAttesterSigned = await Quote.createAttesterSignedQuote(quoteData, keyAlice.getSignCallback(identityAlice))
    // Quote agreement
    bothSigned = await Quote.createQuoteAgreement(
      quoteAttesterSigned,
      legitimation.rootHash,
      keyBob.getSignCallback(identityBob),
      identityBob.uri,
      { didResolveKey }
    )

    // Submit Terms content
    submitTermsContent = {
      claim: {
        cTypeHash: claim.cTypeHash,
      },
      legitimations: [legitimation],
      delegationId: undefined,
      quote: quoteAttesterSigned,
      cTypes: undefined,
    }

    // Request Attestation Content
    requestAttestationContent = {
      credential: legitimation,
      quote: bothSigned,
    }

    // Submit Attestation content
    submitAttestationContent = {
      attestation: {
        delegationId: null,
        claimHash: requestAttestationContent.credential.rootHash,
        cTypeHash: claim.cTypeHash,
        owner: identityBob.uri,
        revoked: false,
      },
    }

    // Request Credential content
    requestCredentialContent = {
      cTypes: [
        {
          cTypeHash: claim.cTypeHash,
          trustedAttesters: [identityAlice.uri],
          requiredProperties: ['id', 'name'],
        },
      ],
      challenge: '1234',
    }
    // Submit Credential content
    submitCredentialContent = [
      {
        ...legitimation,
        claimerSignature: {
          signature: '0x1234',
          keyUri: `${legitimation.claim.owner}#0x1234`,
        },
      },
    ]

    submitTermsBody = {
      content: submitTermsContent,
      type: 'submit-terms',
    }

    requestAttestationBody = {
      content: requestAttestationContent,
      type: 'request-attestation',
    }

    submitAttestationBody = {
      content: submitAttestationContent,
      type: 'submit-attestation',
    }

    rejectAttestationForClaimBody = {
      content: requestAttestationContent.credential.rootHash,
      type: 'reject-attestation',
    }
    requestCredentialBody = {
      content: requestCredentialContent,
      type: 'request-credential',
    }

    submitCredentialBody = {
      content: submitCredentialContent,
      type: 'submit-credential',
    }
  })

  it('Checking required properties for given CType', () => {
    expect(() => verifyRequiredCTypeProperties(['id', 'name'], testCType)).toThrowError(
      MessageError.CTypeUnknownPropertiesError
    )

    expect(() => verifyRequiredCTypeProperties(['id', 'name'], testCTypeWithMultipleProperties)).not.toThrowError(
      MessageError.CTypeUnknownPropertiesError
    )

    expect(() => verifyRequiredCTypeProperties(['id', 'name'], testCTypeWithMultipleProperties)).not.toThrowError()
  })

  beforeAll(async () => {
    messageSubmitTerms = fromBody(submitTermsBody, identityAlice.uri, identityBob.uri)

    messageRequestAttestationForClaim = fromBody(requestAttestationBody, identityAlice.uri, identityBob.uri)
    messageSubmitAttestationForClaim = fromBody(submitAttestationBody, identityAlice.uri, identityBob.uri)

    messageRejectAttestationForClaim = fromBody(rejectAttestationForClaimBody, identityAlice.uri, identityBob.uri)
    messageRequestCredential = fromBody(requestCredentialBody, identityAlice.uri, identityBob.uri)
    messageSubmitCredential = fromBody(submitCredentialBody, identityAlice.uri, identityBob.uri)
  })
  it('message body verifier should not throw errors on correct bodies', () => {
    expect(() => assertKnownMessageBody(messageSubmitTerms)).not.toThrowError()

    expect(() => assertKnownMessageBody(messageRequestAttestationForClaim)).not.toThrowError()
    expect(() => assertKnownMessageBody(messageSubmitAttestationForClaim)).not.toThrowError()
    expect(() => assertKnownMessageBody(messageRejectAttestationForClaim)).not.toThrowError()
    expect(() => assertKnownMessageBody(messageRequestCredential)).not.toThrowError()
    expect(() => assertKnownMessageBody(messageSubmitCredential)).not.toThrowError()
  })

  it('message envelope verifier should not throw errors on correct envelopes', () => {
    expect(() => verifyMessageEnvelope(messageSubmitTerms)).not.toThrowError()
    expect(() => verifyMessageEnvelope(messageRequestAttestationForClaim)).not.toThrowError()
    expect(() => verifyMessageEnvelope(messageSubmitAttestationForClaim)).not.toThrowError()
    expect(() => verifyMessageEnvelope(messageRejectAttestationForClaim)).not.toThrowError()
    expect(() => verifyMessageEnvelope(messageRequestCredential)).not.toThrowError()
    expect(() => verifyMessageEnvelope(messageSubmitCredential)).not.toThrowError()
  })
  it('message envelope verifier should throw errors on faulty envelopes', () => {
    // @ts-ignore
    messageSubmitTerms.sender = 'this is not a sender did'
    expect(() => verifyMessageEnvelope(messageSubmitTerms)).toThrowError(MessageError.InvalidDidFormatError)
    // @ts-ignore
    messageRequestAttestationForClaim.messageId = 12
    expect(() => verifyMessageEnvelope(messageRequestAttestationForClaim)).toThrowError(TypeError)
    // @ts-ignore
    messageSubmitAttestationForClaim.createdAt = '123456'
    expect(() => verifyMessageEnvelope(messageSubmitAttestationForClaim)).toThrowError(TypeError)
    // @ts-ignore
    messageRejectAttestationForClaim.receivedAt = '123456'
    expect(() => verifyMessageEnvelope(messageRejectAttestationForClaim)).toThrowError(TypeError)
    // @ts-ignore
    messageRequestCredential.inReplyTo = 123
    expect(() => verifyMessageEnvelope(messageRequestCredential)).toThrowError(TypeError)
  })
  it('message body verifier should throw errors on faulty bodies', () => {
    submitTermsBody.content.delegationId = 'this is not a delegation id'
    expect(() => assertKnownMessageBody(messageSubmitTerms)).toThrowError(MessageError.HashMalformedError)

    submitCredentialBody.content[0].claimerSignature = {
      signature: 'this is not the claimers signature',
      // @ts-ignore
      keyUri: 'this is not a key id',
    }
    expect(() => assertKnownMessageBody(messageSubmitCredential)).toThrowError()
    // @ts-ignore
    submitAttestationBody.content.attestation.claimHash = 'this is not the claim hash'
    expect(() => assertKnownMessageBody(messageSubmitAttestationForClaim)).toThrowError(
      MessageError.UnknownMessageBodyTypeError
    )
    // @ts-ignore
    rejectAttestationForClaimBody.content = 'this is not the root hash'
    expect(() => assertKnownMessageBody(messageRejectAttestationForClaim)).toThrowError(
      MessageError.UnknownMessageBodyTypeError
    )
    // @ts-ignore
    requestCredentialBody.content.cTypes[0].cTypeHash = 'this is not a cTypeHash'
    expect(() => assertKnownMessageBody(messageRequestCredential)).toThrowError(
      MessageError.UnknownMessageBodyTypeError
    )

    expect(() => assertKnownMessageBody({} as IMessage)).toThrowError(MessageError.UnknownMessageBodyTypeError)
  })
})
