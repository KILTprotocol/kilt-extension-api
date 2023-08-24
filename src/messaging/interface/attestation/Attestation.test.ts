/* eslint-disable @typescript-eslint/ban-ts-comment */
import {
  Attestation,
  CType,
  Claim,
  Did,
  DidDocument,
  DidKey,
  DidResourceUri,
  DidUri,
  IAttestation,
  ICType,
  IClaim,
  ICredential,
  ResolvedDidKey,
  init,
  Credential,
  Quote,
} from '@kiltprotocol/sdk-js'
import { Crypto } from '@kiltprotocol/utils'

import {
  KeyToolSignCallback,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeSigningKeyTool,
} from '../../../tests'
import { receiveSessionRequest, requestSession, verifySession } from '../session'
import { IRequestAttestation, ISession, ISessionRequest, ISubmitTerms, ITerms } from 'src/types'
import {
  confirmPayment,
  receiveAttestation,
  requestAttestation,
  requestPayment,
  submitAttestation,
  submitTerms,
  validateConfirmedPayment,
} from '.'
import { isIRequestCredential, isRequestAttestation, isSubmitCredential, isSubmitTerms } from '../../../utils'
import { decrypt } from '../../Crypto'
import { verifyAttesterSignedQuote, verifyQuoteAgreement } from '../../../quote'

describe('Verifier', () => {
  //Alice
  let aliceLightDid: DidDocument
  let aliceLightDidWithDetails: DidDocument
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSignCallback
  const aliceEncKey = makeEncryptionKeyTool('Alice//enc')

  //Bob
  let bobLightDid: DidDocument
  let bobLightDidWithDetails: DidDocument
  let bobFullDid: DidDocument
  let bobSign: KeyToolSignCallback
  const bobEncKey = makeEncryptionKeyTool('Bob//enc')

  //session
  let sessionRequest: ISessionRequest
  let aliceSession: ISession
  let bobSession: ISession

  //Terms
  let claim: IClaim
  let claimContents: IClaim['contents']
  let testCType: ICType
  let submitTermsContent: ITerms

  //messages
  let requestMessage

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

    sessionRequest = requestSession(aliceFullDid, 'MyApp')
    const { session, sessionResponse } = await receiveSessionRequest(
      bobFullDid,
      sessionRequest,
      bobEncKey.encrypt(bobFullDid),
      bobEncKey.decrypt,
      bobSign(bobFullDid),
      {
        resolveKey,
      }
    )
    bobSession = session

    aliceSession = await verifySession(
      sessionRequest,
      sessionResponse,
      aliceEncKey.decrypt,
      aliceEncKey.encrypt(aliceFullDid),
      aliceSign(aliceFullDid),
      { resolveKey }
    )

    testCType = CType.fromProperties('ClaimCtype', {
      name: { type: 'string' },
    })

    claimContents = {
      name: 'Bob',
    }

    claim = Claim.fromCTypeAndClaimContents(testCType, claimContents, bobFullDid.uri)

    const quoteData = {
      attesterDid: aliceFullDid.uri,
      cTypeHash: claim.cTypeHash,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: new Date(2023, 8, 23).toISOString(),
    }
    // Quote signed by attester
    const quoteAttesterSigned = await Quote.createAttesterSignedQuote(quoteData, aliceSign(aliceFullDid))

    submitTermsContent = {
      claim,
      legitimations: [],
      delegationId: undefined,
      quote: quoteAttesterSigned,
      cTypes: undefined,
    }
  })

  it('submits terms successfully', async () => {
    const { message } = await submitTerms(submitTermsContent, aliceSession, { resolveKey })

    expect(isSubmitTerms(message)).toBeTruthy()
  })

  it('allows Bob to decrypt the message', async () => {
    const { encryptedMessage } = await submitTerms(submitTermsContent, aliceSession, { resolveKey })

    await expect(decrypt(encryptedMessage, bobEncKey.decrypt, { resolveKey })).resolves.not.toThrow()
  })

  it('includes a valid attester-signed quote', async () => {
    const { message } = await submitTerms(submitTermsContent, aliceSession, { resolveKey })

    const messageBody = message.body as ISubmitTerms

    expect(messageBody.content.quote).toBeDefined()
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      verifyAttesterSignedQuote(messageBody.content.quote!, { didResolveKey: resolveKey })
    ).resolves.not.toThrowError()
  })

  it('request credential', async () => {
    const credential = Credential.fromClaim(claim)

    const { encryptedMessage: requestMessageEncrypted, message: requestMessage } = await submitTerms(
      submitTermsContent,
      aliceSession,
      { resolveKey }
    )
    const { encryptedMessage, message } = await requestAttestation(requestMessageEncrypted, credential, bobSession, {
      resolveKey,
    })
    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isRequestAttestation(message)).toBeTruthy()
    const messageBody = message.body as IRequestAttestation
    //   eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(verifyQuoteAgreement(messageBody.content.quote!, { didResolveKey: resolveKey }))

    //Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceEncKey.decrypt, { resolveKey })).resolves.not.toThrow()
  })

  it('request credential without quote', async () => {
    const credential = Credential.fromClaim(claim)

    submitTermsContent.quote = undefined
    const { encryptedMessage: requestMessageEncrypted, message: requestMessage } = await submitTerms(
      submitTermsContent,
      aliceSession,
      { resolveKey }
    )
    const { encryptedMessage, message } = await requestAttestation(requestMessageEncrypted, credential, bobSession, {
      resolveKey,
    })
    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isRequestAttestation(message)).toBeTruthy()
    const messageBody = message.body as IRequestAttestation
    //   eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(messageBody.content.quote!).toBeUndefined()

    //Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceEncKey.decrypt, { resolveKey })).resolves.not.toThrow()
  })

  it('request payment', async () => {
    const credential = Credential.fromClaim(claim)
    const { encryptedMessage: requestMessageEncrypted } = await submitTerms(submitTermsContent, aliceSession, {
      resolveKey,
    })
    const { encryptedMessage } = await requestAttestation(requestMessageEncrypted, credential, bobSession, {
      resolveKey,
    })
  })
})
