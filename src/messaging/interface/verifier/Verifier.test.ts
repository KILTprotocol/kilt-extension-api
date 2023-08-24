/* eslint-disable @typescript-eslint/ban-ts-comment */
import { Did, DidDocument, DidKey, DidResourceUri, ResolvedDidKey, init, Credential } from '@kiltprotocol/sdk-js'
import { Crypto } from '@kiltprotocol/utils'

import {
  KeyToolSignCallback,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeSigningKeyTool,
} from '../../../tests'
import { receiveSessionRequest, requestSession, verifySession } from '../session'
import { IRequestCredential, ISession, ISessionRequest, ISubmitCredential } from '../../../types'
import { requestCredential, submitCredential, verifySubmitedCredentialMessage } from '.'
import { isIRequestCredential, isSubmitCredential } from '../../../utils'
import { decrypt } from '../../MessageEnvelope.'

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
  })

  it('should successfully request a valid credential', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]

    const requestedCredential = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    expect(requestedCredential.encryptedMessage).toBeDefined()
    expect(requestedCredential.message).toBeDefined()
    expect(requestedCredential.challenge).toBeDefined()
  })

  it('should include session information in the requested credential', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]

    const requestedCredential = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    const { senderEncryptionKeyUri, receiverEncryptionKeyUri } = aliceSession

    expect(requestedCredential.message.sender).toBe(Did.parse(senderEncryptionKeyUri).did)
    expect(requestedCredential.message.receiver).toBe(Did.parse(receiverEncryptionKeyUri).did)
  })

  it('should include challenge in the requested credential', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]
    const requestedCredential = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })
    expect(requestedCredential.challenge).toHaveLength(50)
  })

  it('should request a credential with owner information', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]
    const owner = aliceFullDid.uri

    const requestedCredential = await requestCredential(aliceSession, cTypes, owner, { resolveKey })

    expect(isIRequestCredential(requestedCredential.message)).toBeTruthy()

    expect((requestedCredential.message.body as IRequestCredential).content.owner).toBe(owner)
  })

  it('should throw an error if session is missing receiverEncryptionKeyUri', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]
    const invalidSession = { ...aliceSession, receiverEncryptionKeyUri: undefined }

    //@ts-ignore
    await expect(requestCredential(invalidSession, cTypes, undefined, { resolveKey })).rejects.toThrowError()
  })

  it('Bob should be able to decrypt the message', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]

    const { encryptedMessage } = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    expect(async () => await decrypt(encryptedMessage, bobEncKey.decrypt, { resolveKey })).not.toThrowError()
  })

  it('submit credential', async () => {
    const cTypeHash = Crypto.hashStr('0x12345678')
    const credential = Credential.fromClaim({
      cTypeHash,
      owner: aliceFullDid.uri,
      contents: {},
    })

    const cTypes = [{ cTypeHash }]

    const { encryptedMessage, message } = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    const response = await submitCredential([credential], encryptedMessage, bobSession, { resolveKey })

    // Alice should be able to decrypt the message
    const decryptedMessage = await decrypt(response, aliceEncKey.decrypt, { resolveKey })

    expect(decryptedMessage.inReplyTo).toBe(message.messageId)
    expect(isSubmitCredential(decryptedMessage)).toBeTruthy()
    const body = decryptedMessage.body as ISubmitCredential
    expect(body.content[0].claim.cTypeHash).toBe(cTypeHash)
  })

  it('Bob should be able to decrypt the message', async () => {
    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]

    const { encryptedMessage } = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    expect(async () => await decrypt(encryptedMessage, bobEncKey.decrypt, { resolveKey })).not.toThrowError()
  })

  it('submit credential with wrong ctype hash', async () => {
    const credential = Credential.fromClaim({
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: aliceFullDid.uri,
      contents: {},
    })

    const cTypes = [{ cTypeHash: Crypto.hashStr('0x123456789') }]

    const { encryptedMessage } = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    await expect(submitCredential([credential], encryptedMessage, bobSession, { resolveKey })).rejects.toThrowError()
  })

  it('submit credential with wrong owner', async () => {
    const credential = Credential.fromClaim({
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobFullDid.uri,
      contents: {},
    })

    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]

    const { encryptedMessage } = await requestCredential(aliceSession, cTypes, aliceFullDid.uri, { resolveKey })

    await expect(submitCredential([credential], encryptedMessage, bobSession, { resolveKey })).rejects.toThrowError()
  })

  it('Alice should be able to decrypt the message', async () => {
    const credential = Credential.fromClaim({
      cTypeHash: Crypto.hashStr('0x12345678'),
      owner: bobFullDid.uri,
      contents: {},
    })

    const cTypes = [{ cTypeHash: Crypto.hashStr('0x12345678') }]

    const { encryptedMessage } = await requestCredential(aliceSession, cTypes, undefined, { resolveKey })

    const credentialMessage = await submitCredential([credential], encryptedMessage, bobSession, { resolveKey })

    expect(async () => await decrypt(credentialMessage, aliceEncKey.decrypt, { resolveKey })).not.toThrowError()
  })

  it('verify submited Credential', async () => {
    const cTypeHash = Crypto.hashStr('0x12345678')
    const credential = Credential.fromClaim({
      cTypeHash,
      owner: aliceFullDid.uri,
      contents: {},
    })

    const cTypes = [{ cTypeHash }]

    const requestMessage = await requestCredential(aliceSession, cTypes, undefined, {
      resolveKey,
    })

    const responeMessage = await submitCredential([credential], requestMessage.encryptedMessage, bobSession, {
      resolveKey,
    })

    //TODO ask how I can do that.
    // expect(
    //   async () => await verifySubmitedCredentialMessage(responeMessage, aliceSession, requestMessage, { resolveKey })
    // ).not.toThrowError()
  })
})
