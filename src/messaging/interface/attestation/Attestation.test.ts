/* eslint-disable @typescript-eslint/ban-ts-comment */
import { Did, DidDocument, DidKey, DidResourceUri, ResolvedDidKey, init } from '@kiltprotocol/sdk-js'

import {
  KeyToolSignCallback,
  createLocalDemoFullDidFromLightDid,
  makeEncryptionKeyTool,
  makeSigningKeyTool,
} from '../../../tests'
import { receiveSessionRequest, requestSession, verifySession } from '../session'
import { ISession, ISessionRequest } from 'src/types'
import {
  confirmPayment,
  receiveAttestation,
  requestAttestation,
  requestPayment,
  submitAttestation,
  submitTerms,
  validateConfirmedPayment,
} from '.'
import { isIRequestCredential, isSubmitCredential } from '../../../utils'
import { decrypt } from '../../Crypto'

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
})
