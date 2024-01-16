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

import { Attestation, CType } from '@kiltprotocol/credentials'
import { createLightDidDocument, multibaseKeyToDidKey, parse } from '@kiltprotocol/did'
import { Claim, Credential } from '@kiltprotocol/legacy-credentials'
import { DidResolver, init } from '@kiltprotocol/sdk-js'
import type {
  Did,
  DidDocument,
  DidUrl,
  IAttestation,
  ICType,
  IClaim,
  ICredential,
  ICredentialPresentation,
  SignerInterface,
} from '@kiltprotocol/types'
import { Crypto, Signers } from '@kiltprotocol/utils'
import { u8aToHex } from '@polkadot/util'
import { createAttesterSignedQuote, createQuoteAgreement } from '../quote/Quote'
import {
  KeyTool,
  createLocalDemoFullDidFromKeypair,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeMockDereference,
  makeSigningKeyTool,
} from '../tests'
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
import { assertKnownMessage, assertKnownMessageBody, ensureOwnerIsSender } from './CredentialApiMessageType'
import * as MessageError from './Error'
import { decrypt, encrypt, verifyMessageEnvelope } from './MessageEnvelope'
import { fromBody, verifyRequiredCTypeProperties } from './utils'

describe('Messaging', () => {
  let mockDereference: ReturnType<typeof makeMockDereference>

  let aliceLightDid: DidDocument
  let aliceLightDidWithDetails: DidDocument
  let aliceFullDid: DidDocument
  let aliceSign: SignerInterface[]
  let aliceAuthentication: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>
  const aliceEncKey = makeEncryptionKeyTool('Alice//enc')

  let bobLightDid: DidDocument
  let bobLightDidWithDetails: DidDocument
  let bobFullDid: DidDocument
  let bobAuthentication: SignerInterface<Signers.DidPalletSupportedAlgorithms, DidUrl>
  const bobEncKey = makeEncryptionKeyTool('Bob//enc')

  beforeAll(async () => {
    await init()
    const aliceAuthKey = await makeSigningKeyTool('ed25519')
    aliceLightDid = createLightDidDocument({
      authentication: aliceAuthKey.authentication,
      keyAgreement: aliceEncKey.keyAgreement,
    })
    aliceLightDidWithDetails = createLightDidDocument({
      authentication: aliceAuthKey.authentication,
      keyAgreement: aliceEncKey.keyAgreement,
      service: [{ id: '#id-1', type: ['type-1'], serviceEndpoint: ['x:url-1'] }],
    })
    aliceFullDid = await createLocalDemoFullDidFromLightDid(aliceLightDid)
    aliceSign = await aliceAuthKey.getSigners(aliceFullDid)
    aliceAuthentication = (
      await aliceAuthKey.getSigners<Signers.DidPalletSupportedAlgorithms>(aliceFullDid, {
        verificationRelationship: 'authentication',
        algorithms: Signers.DID_PALLET_SUPPORTED_ALGORITHMS,
      })
    )[0]

    const bobAuthKey = await makeSigningKeyTool('ed25519')
    bobLightDid = createLightDidDocument({
      authentication: bobAuthKey.authentication,
      keyAgreement: bobEncKey.keyAgreement,
    })
    bobLightDidWithDetails = createLightDidDocument({
      authentication: bobAuthKey.authentication,
      keyAgreement: bobEncKey.keyAgreement,
      service: [{ id: '#id-1', type: ['type-1'], serviceEndpoint: ['x:url-1'] }],
    })
    bobFullDid = await createLocalDemoFullDidFromLightDid(bobLightDid)
    bobAuthentication = (
      await bobAuthKey.getSigners<Signers.DidPalletSupportedAlgorithms>(bobFullDid, {
        verificationRelationship: 'authentication',
        algorithms: Signers.DID_PALLET_SUPPORTED_ALGORITHMS,
      })
    )[0]

    mockDereference = makeMockDereference([
      aliceLightDidWithDetails,
      aliceLightDid,
      aliceFullDid,
      bobLightDidWithDetails,
      bobLightDid,
      bobFullDid,
    ])
  })

  it('verify message encryption and signing', async () => {
    const message = fromBody(
      {
        type: 'request-credential',
        content: {
          cTypes: [{ cTypeHash: `${Crypto.hashStr('0x12345678')}` }],
        },
      },
      aliceLightDid.id,
      bobLightDid.id
    )
    const encryptedMessage = await encrypt(
      message,
      aliceEncKey.encrypt(aliceLightDid),
      `${bobLightDid.id}#encryption`,
      { dereferenceDidUrl: mockDereference }
    )

    const decryptedMessage = await decrypt(encryptedMessage, bobEncKey.decrypt, { dereferenceDidUrl: mockDereference })
    expect(JSON.stringify(message.body)).toEqual(JSON.stringify(decryptedMessage.body))

    expect(() => assertKnownMessage(decryptedMessage)).not.toThrow()

    const encryptedMessageWrongContent = JSON.parse(
      JSON.stringify(encryptedMessage)
    ) as IEncryptedMessage<IRequestCredential>
    const messedUpContent = Crypto.coToUInt8(encryptedMessageWrongContent.ciphertext)
    messedUpContent.set(Crypto.hash('1234'), 10)
    encryptedMessageWrongContent.ciphertext = u8aToHex(messedUpContent)

    await expect(() =>
      decrypt(encryptedMessageWrongContent, bobEncKey.decrypt, { dereferenceDidUrl: mockDereference })
    ).rejects.toThrowError(MessageError.DecodingMessageError)

    const encryptedWrongBody = await aliceEncKey.encrypt(aliceLightDid)({
      data: Crypto.coToUInt8('{ wrong JSON'),
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      peerPublicKey: multibaseKeyToDidKey(
        bobLightDid.verificationMethod?.find(({ id }) => id === bobLightDid.keyAgreement![0])?.publicKeyMultibase ?? 'z'
      ).publicKey,
      did: aliceLightDid.id,
    })
    const encryptedMessageWrongBody: IEncryptedMessage<IRequestCredential> = {
      ciphertext: u8aToHex(encryptedWrongBody.data),
      nonce: u8aToHex(encryptedWrongBody.nonce),
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      senderKeyUri: `${aliceLightDid.id}${aliceLightDid.keyAgreement![0]}`,
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      receiverKeyUri: `${bobLightDid.id}${bobLightDid.keyAgreement![0]}`,
    }
    await expect(() =>
      decrypt(encryptedMessageWrongBody, bobEncKey.decrypt, { dereferenceDidUrl: mockDereference })
    ).rejects.toThrowError(SyntaxError)
  })

  it('verifies the message with sender is the owner (as full DID)', async () => {
    const credential = Credential.fromClaim({
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      owner: aliceFullDid.id,
      contents: {},
    })

    const presentation = await Credential.createPresentation({
      credential,
      signers: aliceSign,
      didDocument: aliceFullDid,
    })

    const date = new Date(2019, 11, 10).toISOString()

    const quoteData: IQuote = {
      attesterDid: bobFullDid.id,
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
    const quoteAttesterSigned = await createAttesterSignedQuote(quoteData, bobAuthentication)
    const bothSigned = await createQuoteAgreement(
      quoteAttesterSigned,
      credential.rootHash,
      aliceAuthentication,
      aliceFullDid.id,
      { dereferenceDidUrl: mockDereference }
    )
    const requestAttestationBody: IRequestAttestation = {
      content: {
        credential,
        quote: bothSigned,
      },
      type: 'request-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceFullDid.id, bobFullDid.id))).not.toThrow()

    // Should not throw if the sender is the light DID version of the owner.
    // This is technically not to be allowed but message verification is not concerned with that.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceLightDid.id, bobFullDid.id))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, bobFullDid.id, aliceFullDid.id))).toThrowError(
      MessageError.IdentityMismatchError
    )

    const attestation = {
      delegationId: null,
      claimHash: requestAttestationBody.content.credential.rootHash,
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobFullDid.id,
      revoked: false,
    }

    const submitAttestationBody: ISubmitAttestation = {
      content: {
        attestation,
      },
      type: 'submit-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobFullDid.id, aliceFullDid.id))).not.toThrow()

    // Should not throw if the sender is the light DID version of the owner.
    // This is technically not to be allowed but message verification is not concerned with that.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobLightDid.id, aliceFullDid.id))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, aliceFullDid.id, bobFullDid.id))).toThrowError(
      MessageError.IdentityMismatchError
    )

    const submitClaimsForCTypeBody: ISubmitCredential = {
      content: [presentation],
      type: 'submit-credential',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceFullDid.id, bobFullDid.id))).not.toThrow()

    // Should not throw if the sender is the light DID version of the owner.
    // This is technically not to be allowed but message verification is not concerned with that.
    expect(() => ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceLightDid.id, bobFullDid.id))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, bobFullDid.id, aliceFullDid.id))).toThrowError(
      MessageError.IdentityMismatchError
    )
  })

  it('verifies the message with sender is the owner (as light DID)', async () => {
    // Create request for attestation to the light DID with no encoded details
    const credential = Credential.fromClaim({
      cTypeHash: `${Crypto.hashStr('0x12345678')}`,
      owner: aliceLightDid.id,
      contents: {},
    })

    const presentation = await Credential.createPresentation({
      credential,
      signers: aliceSign,
      didDocument: aliceFullDid,
    })

    const date = new Date(2019, 11, 10).toISOString()
    const quoteData: IQuote = {
      attesterDid: bobLightDid.id,
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
    const quoteAttesterSigned = await createAttesterSignedQuote(quoteData, bobAuthentication)
    const bothSigned = await createQuoteAgreement(
      quoteAttesterSigned,
      credential.rootHash,
      aliceAuthentication,
      aliceLightDid.id,
      { dereferenceDidUrl: mockDereference }
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
        owner: aliceLightDidWithDetails.id,
        contents: {},
      }),
      signers: aliceSign,
      didDocument: aliceFullDid,
    })

    const quoteDataEncodedDetails: IQuote = {
      attesterDid: bobLightDidWithDetails.id,
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
    const quoteAttesterSignedEncodedDetails = await createAttesterSignedQuote(
      quoteDataEncodedDetails,
      bobAuthentication
    )
    const bothSignedEncodedDetails = await createQuoteAgreement(
      quoteAttesterSignedEncodedDetails,
      credential.rootHash,
      aliceAuthentication,
      aliceLightDidWithDetails.id,
      { dereferenceDidUrl: mockDereference }
    )
    const requestAttestationBodyWithEncodedDetails: IRequestAttestation = {
      content: {
        credential: contentWithEncodedDetails,
        quote: bothSignedEncodedDetails,
      },
      type: 'request-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceLightDid.id, bobLightDid.id))).not.toThrow()

    // Should not throw if the owner has no additional details and the sender does.
    expect(() =>
      ensureOwnerIsSender(
        fromBody(requestAttestationBodyWithEncodedDetails, aliceLightDidWithDetails.id, bobLightDid.id)
      )
    ).not.toThrow()

    // Should not throw if the owner has additional details and the sender does not.
    expect(() =>
      ensureOwnerIsSender(fromBody(requestAttestationBodyWithEncodedDetails, aliceLightDid.id, bobLightDid.id))
    ).not.toThrow()

    // Should not throw if the sender is the full DID version of the owner.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, aliceFullDid.id, bobLightDid.id))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(requestAttestationBody, bobLightDid.id, aliceLightDid.id))).toThrowError(
      MessageError.IdentityMismatchError
    )

    const attestation = {
      delegationId: null,
      claimHash: requestAttestationBody.content.credential.rootHash,
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobLightDid.id,
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
      owner: bobLightDidWithDetails.id,
      revoked: false,
    }

    const submitAttestationBodyWithEncodedDetails: ISubmitAttestation = {
      content: {
        attestation: attestationWithEncodedDetails,
      },
      type: 'submit-attestation',
    }

    // Should not throw if the owner and sender DID is the same.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobLightDid.id, aliceLightDid.id))).not.toThrow()

    // Should not throw if the owner has no additional details and the sender does.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitAttestationBody, bobLightDidWithDetails.id, aliceLightDid.id))
    ).not.toThrow()

    // Should not throw if the owner has additional details and the sender does not.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitAttestationBodyWithEncodedDetails, bobLightDid.id, aliceLightDid.id))
    ).not.toThrow()

    // Should not throw if the sender is the full DID version of the owner.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, bobFullDid.id, aliceLightDid.id))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() => ensureOwnerIsSender(fromBody(submitAttestationBody, aliceLightDid.id, bobLightDid.id))).toThrowError(
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
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceLightDid.id, bobLightDid.id))
    ).not.toThrow()

    // Should not throw if the owner has no additional details and the sender does.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceLightDidWithDetails.id, bobLightDid.id))
    ).not.toThrow()

    // Should not throw if the owner has additional details and the sender does not.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBodyWithEncodedDetails, aliceLightDid.id, bobLightDid.id))
    ).not.toThrow()

    // Should not throw if the sender is the full DID version of the owner.
    expect(() => ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, aliceFullDid.id, bobLightDid.id))).not.toThrow()

    // Should throw if the sender and the owner are two different entities.
    expect(() =>
      ensureOwnerIsSender(fromBody(submitClaimsForCTypeBody, bobLightDid.id, aliceLightDid.id))
    ).toThrowError(MessageError.IdentityMismatchError)
  })
})

describe('Error checking / Verification', () => {
  // TODO: Duplicated code, would be nice to have as a seperated test package with similar helpers
  async function buildCredential(
    claimerDid: Did,
    attesterDid: Did,
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

    keyAlice = await makeSigningKeyTool()
    identityAlice = await createLocalDemoFullDidFromKeypair(keyAlice.keypair)
    keyBob = await makeSigningKeyTool()
    identityBob = await createLocalDemoFullDidFromKeypair(keyBob.keypair)

    date = new Date(2019, 11, 10).toISOString()
    claimContents = {
      name: 'Bob',
    }

    async function didmockDereference(keyUri: Did | DidUrl): ReturnType<typeof DidResolver.dereference> {
      const { did, fragment } = parse(keyUri)
      const document = [identityAlice, identityBob].find(({ id }) => id === did)
      if (!document) throw new Error('Cannot resolve mocked DID')
      let result
      if (!fragment) {
        result = document
      } else {
        result = document.verificationMethod?.find(({ id }) => id === document.authentication?.[0])
      }
      return {
        contentStream: result,
        contentMetadata: {},
        dereferencingMetadata: {} as any,
      }
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
    claim = Claim.fromCTypeAndClaimContents(testCType, claimContents, identityAlice.id)
    // Legitimation
    ;[legitimation] = await buildCredential(identityAlice.id, identityBob.id, {}, [])
    // Quote Data
    quoteData = {
      attesterDid: identityAlice.id,
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
    const aliceAuthentication = (
      await keyAlice.getSigners<Signers.DidPalletSupportedAlgorithms>(identityAlice, {
        verificationRelationship: 'authentication',
        algorithms: Signers.DID_PALLET_SUPPORTED_ALGORITHMS,
      })
    )[0]
    quoteAttesterSigned = await createAttesterSignedQuote(quoteData, aliceAuthentication)
    // Quote agreement
    const bobAuthentication = (
      await keyAlice.getSigners<Signers.DidPalletSupportedAlgorithms>(identityBob, {
        verificationRelationship: 'authentication',
        algorithms: Signers.DID_PALLET_SUPPORTED_ALGORITHMS,
      })
    )[0]
    bothSigned = await createQuoteAgreement(
      quoteAttesterSigned,
      legitimation.rootHash,
      bobAuthentication,
      identityBob.id,
      {
        dereferenceDidUrl: didmockDereference,
      }
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
        owner: identityBob.id,
        revoked: false,
      },
    }

    // Request Credential content
    requestCredentialContent = {
      cTypes: [
        {
          cTypeHash: claim.cTypeHash,
          trustedAttesters: [identityAlice.id],
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
    messageSubmitTerms = fromBody(submitTermsBody, identityAlice.id, identityBob.id)

    messageRequestAttestationForClaim = fromBody(requestAttestationBody, identityAlice.id, identityBob.id)
    messageSubmitAttestationForClaim = fromBody(submitAttestationBody, identityAlice.id, identityBob.id)

    messageRejectAttestationForClaim = fromBody(rejectAttestationForClaimBody, identityAlice.id, identityBob.id)
    messageRequestCredential = fromBody(requestCredentialBody, identityAlice.id, identityBob.id)
    messageSubmitCredential = fromBody(submitCredentialBody, identityAlice.id, identityBob.id)
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
    expect(() => verifyMessageEnvelope(messageSubmitTerms)).toThrowError()
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
    expect(() => assertKnownMessageBody(messageSubmitTerms)).toThrowError()

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
