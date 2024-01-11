/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { createLightDidDocument, multibaseKeyToDidKey } from '@kiltprotocol/did'
import { init } from '@kiltprotocol/sdk-js'
import type { DidDocument, VerificationMethod } from '@kiltprotocol/types'
import { u8aEq, u8aToString } from '@polkadot/util'
import { receiveSessionRequest, requestSession, verifySession } from '.'
import {
  KeyToolSigners,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeMockDereference,
  makeSigningKeyTool,
} from '../../../tests'
import type { ISession, ISessionRequest, ISessionResponse } from '../../../types'
import { KeyError } from '../../Error'

describe('Session', () => {
  let dereferenceDidUrl: ReturnType<typeof makeMockDereference>
  //Alice
  let aliceLightDid: DidDocument
  let aliceLightDidWithDetails: DidDocument
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSigners
  const aliceEncKey = makeEncryptionKeyTool('Alice//enc')

  //Bob
  let bobLightDid: DidDocument
  let bobLightDidWithDetails: DidDocument
  let bobFullDid: DidDocument
  let bobSign: KeyToolSigners
  const bobEncKey = makeEncryptionKeyTool('Bob//enc')

  //session
  let sessionRequest: ISessionRequest
  let sessionResponse: { session: ISession; sessionResponse: ISessionResponse }

  beforeAll(async () => {
    await init()
    const aliceAuthKey = await makeSigningKeyTool('ed25519')
    aliceSign = aliceAuthKey.getSigners
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

    const bobAuthKey = await makeSigningKeyTool('ed25519')
    bobSign = bobAuthKey.getSigners
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

    dereferenceDidUrl = makeMockDereference([
      aliceLightDidWithDetails,
      aliceLightDid,
      aliceFullDid,
      bobLightDidWithDetails,
      bobLightDid,
      bobFullDid,
    ])

    sessionRequest = requestSession(aliceFullDid, 'MyApp')
    sessionResponse = await receiveSessionRequest(
      bobFullDid,
      sessionRequest,
      bobEncKey.encrypt(bobFullDid),
      bobEncKey.decrypt,
      await bobSign(bobFullDid),
      {
        dereferenceDidUrl,
      }
    )
  })
  it('should create a valid session request', () => {
    const result: ISessionRequest = requestSession(aliceFullDid, 'MyApp')

    const encryptionKeyUri = `${aliceFullDid.id}${aliceFullDid.keyAgreement?.[0]}`
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
      await bobSign(bobFullDid),
      { dereferenceDidUrl }
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
      verificationMethod: sessionRequest.encryptionKeyUri,
    })
    const decryptedChallenge = u8aToString(decryptedChallengeBytes.data)
    expect(decryptedChallenge).toBe(challenge)

    const { contentStream: bobsEncryptionKey } = await dereferenceDidUrl(encryptionKeyUri)
    const dereferencedKey = multibaseKeyToDidKey((bobsEncryptionKey as VerificationMethod).publicKeyMultibase).publicKey
    expect(u8aEq(bobEncKey.keyAgreement[0].publicKey, dereferencedKey)).toBe(true)
  })

  it('provide legit session response', async () => {
    expect(
      async () =>
        await verifySession(
          sessionRequest,
          sessionResponse.sessionResponse,
          aliceEncKey.decrypt,
          aliceEncKey.encrypt(aliceFullDid),
          await aliceSign(aliceFullDid),
          { dereferenceDidUrl }
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
        await aliceSign(aliceFullDid),
        { dereferenceDidUrl }
      )
    ).rejects.toThrowError('Invalid challenge')
  })
})
