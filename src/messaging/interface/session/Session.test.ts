import { Did, DidDocument, DidResourceUri, init } from '@kiltprotocol/sdk-js'

import { KeyTool, createLocalDemoFullDidFromKeypair, makeSigningKeyTool } from '../../../tests'
import { requestSession } from '.'
import { IRequestSession } from 'src/types'
import { KeyError } from '../../Error'

describe('Session', () => {
  let keyAlice: KeyTool
  let identityAlice: DidDocument

  let keyBob: KeyTool
  let identityBob: DidDocument

  beforeAll(async () => {
    await init()
    keyAlice = makeSigningKeyTool()
    identityAlice = await createLocalDemoFullDidFromKeypair(keyAlice.keypair)
    keyBob = makeSigningKeyTool()
    identityBob = await createLocalDemoFullDidFromKeypair(keyBob.keypair)
  })

  it('Create valid session request', () => {
    const result: IRequestSession = requestSession(identityAlice, 'MyApp')
    expect(result.name).toBe('MyApp')
    expect(Did.validateUri(result.encryptionKeyUri)).toBe(undefined)
    expect(result.challenge.length).toBe(50)
  })

  it('Create invalid session', () => {
    identityBob.keyAgreement = undefined
    expect(() => requestSession(identityBob, 'MyApp')).toThrowError(KeyError)
  })

  it('Receive Session Request', () => {
    const encryptionKeyUri = `${identityAlice.uri}${identityAlice.keyAgreement?.[0].id}` as DidResourceUri
    const session_request: IRequestSession = requestSession(identityAlice, 'MyApp')
  })
})
