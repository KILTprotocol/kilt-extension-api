import { Did, DidDocument, DidKey, DidResourceUri, ResolvedDidKey, init } from '@kiltprotocol/sdk-js'

import {
  KeyToolSignCallback,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeSigningKeyTool,
} from '../../../tests'
import { receiveSessionRequest, requestSession, verifySession } from '.'
import { ISession, ISessionRequest, ISessionResponse } from 'src/types'
import { KeyError } from '../../Error'
import { u8aToString } from '@polkadot/util'

describe('Session', () => {
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
  let sessionResponse: { session: ISession; sessionResponse: ISessionResponse }

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
    sessionResponse = await receiveSessionRequest(
      bobFullDid,
      sessionRequest,
      bobEncKey.encrypt(bobFullDid),
      bobEncKey.decrypt,
      bobSign(bobFullDid),
      {
        resolveKey,
      }
    )
  })
  it('should create a valid session request', () => {
    const result: ISessionRequest = requestSession(aliceFullDid, 'MyApp')

    const encryptionKeyUri = `${aliceFullDid.uri}${aliceFullDid.keyAgreement?.[0].id}` as DidResourceUri
    expect(result.name).toBe('MyApp')
    expect(result.encryptionKeyUri).toBe(encryptionKeyUri)
    expect(result.challenge).toHaveLength(50)
  })

  it('should throw an error when creating an invalid session request', () => {
    const copyBobFullDid = { ...bobFullDid, keyAgreement: undefined }
    expect(() => requestSession(copyBobFullDid, 'MyApp')).toThrowError(KeyError)
  })

  it('should receive and process a valid session request', async () => {
    const response = await receiveSessionRequest(
      bobFullDid,
      sessionRequest,
      bobEncKey.encrypt(bobFullDid),
      bobEncKey.decrypt,
      bobSign(bobFullDid),
      { resolveKey }
    )

    const { session, sessionResponse } = response
    const { receiverEncryptionKeyUri } = session
    const { encryptedChallenge, nonce, encryptionKeyUri } = sessionResponse
    const { challenge } = sessionRequest

    expect(receiverEncryptionKeyUri).toBe(sessionRequest.encryptionKeyUri)

    const decryptedChallengeBytes = await aliceEncKey.decrypt({
      data: encryptedChallenge,
      nonce: nonce,
      peerPublicKey: bobEncKey.keyAgreement[0].publicKey,
      keyUri: sessionRequest.encryptionKeyUri,
    })
    const decryptedChallenge = u8aToString(decryptedChallengeBytes.data)
    expect(decryptedChallenge).toBe(challenge)

    const bobsEncryptionKey = await resolveKey(encryptionKeyUri, 'keyAgreement')
    expect(bobsEncryptionKey.publicKey).toBe(bobEncKey.keyAgreement[0].publicKey)
  })

  it('provide legit session response', async () => {
    expect(
      async () =>
        await verifySession(
          sessionRequest,
          sessionResponse.sessionResponse,
          aliceEncKey.decrypt,
          aliceEncKey.encrypt(aliceFullDid),
          aliceSign(aliceFullDid),
          { resolveKey }
        )
    )
  })

  it('should throw an error when session verification fails', async () => {
    // Intentionally altering the challenge
    const alteredChallenge = sessionRequest.challenge + 'A'
    const alteredSessionRequest = { ...sessionRequest, challenge: alteredChallenge }

    await expect(
      verifySession(
        alteredSessionRequest,
        sessionResponse.sessionResponse,
        aliceEncKey.decrypt,
        aliceEncKey.encrypt(aliceFullDid),
        aliceSign(aliceFullDid),
        { resolveKey }
      )
    ).rejects.toThrowError('Invalid challenge')
  })
})
