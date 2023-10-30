/* eslint-disable @typescript-eslint/ban-ts-comment */
import {
  Did,
  DidDocument,
  Credential,
  KiltKeyringPair,
  DecryptCallback,
  EncryptCallback,
  connect,
  ICType,
  CType,
  CTypeHash,
  IClaim,
  Claim,
  ICredential,
} from '@kiltprotocol/sdk-js'
import { BN } from '@polkadot/util'
import { Crypto } from '@kiltprotocol/utils'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import Keyring from '@polkadot/keyring'

import {
  KeyToolSignCallback,
  createAttestation,
  createCtype,
  fundAccount,
  generateDid,
  keypairs,
  makeDecryptCallback,
  makeEncryptCallback,
  makeSignCallback,
  startContainer,
} from '../../../tests'
import { receiveSessionRequest, requestSession, verifySession } from '../session'
import { IRequestCredential, ISession, ISessionRequest, ISubmitCredential } from '../../../types'
import { requestCredential, submitCredential, verifySubmittedCredentialMessage } from '.'
import { isIRequestCredential, isSubmitCredential } from '../../../utils'
import { decrypt } from '../../MessageEnvelope'

describe('Verifier', () => {
  //Alice
  let aliceAccount: KiltKeyringPair
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSignCallback
  let aliceSignAssertion: KeyToolSignCallback
  let aliceDecryptCallback: DecryptCallback
  let aliceEncryptCallback: EncryptCallback

  //Bob
  let bobFullDid: DidDocument
  let bobSign: KeyToolSignCallback
  let bobDecryptCallback: DecryptCallback
  let bobEncryptCallback: EncryptCallback

  //session
  let sessionRequest: ISessionRequest
  let aliceSession: ISession
  let bobSession: ISession

  //Ctypes
  let testCType: ICType
  let cTypeHash: CTypeHash
  let claimContents: IClaim['contents']

  //Credential
  let credential: ICredential

  beforeAll(async () => {
    const address = await startContainer()
    await connect(address)
  }, 20_000)

  beforeAll(async () => {
    // Setup Alice
    const aliceMnemonic = mnemonicGenerate()
    aliceAccount = new Keyring({}).addFromMnemonic(aliceMnemonic) as KiltKeyringPair
    await fundAccount(aliceAccount.address, new BN('10000000000000000'))
    aliceFullDid = await generateDid(aliceAccount, aliceMnemonic)
    const keyPairsAlice = await keypairs(aliceMnemonic)
    aliceEncryptCallback = makeEncryptCallback(keyPairsAlice.keyAgreement)(aliceFullDid)
    aliceDecryptCallback = makeDecryptCallback(keyPairsAlice.keyAgreement)
    aliceSign = makeSignCallback(keyPairsAlice.authentication)
    aliceSignAssertion = makeSignCallback(keyPairsAlice.assertionMethod)

    // Setup Bob
    const bobMnemonic = mnemonicGenerate()
    const bobAccount = new Keyring({}).addFromMnemonic(bobMnemonic) as KiltKeyringPair
    await fundAccount(bobAccount.address, new BN('10000000000000000'))
    bobFullDid = await generateDid(bobAccount, bobMnemonic)
    const keyPairsBob = await keypairs(bobMnemonic)
    bobEncryptCallback = makeEncryptCallback(keyPairsBob.keyAgreement)(bobFullDid)
    bobDecryptCallback = makeDecryptCallback(keyPairsBob.keyAgreement)
    bobSign = makeSignCallback(keyPairsBob.authentication)

    // Session Setup
    sessionRequest = requestSession(aliceFullDid, 'MyApp')
    const { session, sessionResponse } = await receiveSessionRequest(
      bobFullDid,
      sessionRequest,
      bobEncryptCallback,
      bobDecryptCallback,
      bobSign(bobFullDid)
    )
    bobSession = session
    aliceSession = await verifySession(
      sessionRequest,
      sessionResponse,
      aliceDecryptCallback,
      aliceEncryptCallback,
      aliceSign(aliceFullDid)
    )

    // CType and Credential Setup
    testCType = CType.fromProperties('testCtype', { name: { type: 'string' } })
    await createCtype(aliceFullDid.uri, aliceAccount, aliceMnemonic, testCType)

    claimContents = { name: 'Bob' }
    const claim = Claim.fromCTypeAndClaimContents(testCType, claimContents, bobFullDid.uri)
    cTypeHash = claim.cTypeHash
    credential = Credential.fromClaim(claim)

    await createAttestation(
      aliceAccount,
      aliceFullDid.uri,
      aliceSignAssertion(aliceFullDid),
      credential.rootHash,
      cTypeHash
    )
  }, 40000)

  describe('Credential Request and Submission', () => {
    it('should successfully request a valid credential', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const requestedCredential = await requestCredential(aliceSession, cTypes)
      expect(requestedCredential.encryptedMessage).toBeDefined()
      expect(requestedCredential.message).toBeDefined()
      expect(requestedCredential.challenge).toBeDefined()
    })

    it('should include session information in the requested credential', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const requestedCredential = await requestCredential(aliceSession, cTypes)

      const { senderEncryptionKeyUri, receiverEncryptionKeyUri } = aliceSession
      const senderDid = Did.parse(senderEncryptionKeyUri).did
      const receiverDid = Did.parse(receiverEncryptionKeyUri).did

      expect(requestedCredential.message.sender).toBe(senderDid)
      expect(requestedCredential.message.receiver).toBe(receiverDid)
    })

    it('should include challenge in the requested credential', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const requestedCredential = await requestCredential(aliceSession, cTypes)
      expect(requestedCredential.challenge).toHaveLength(50)
    })

    it('should request a credential with owner information', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const owner = aliceFullDid.uri
      const requestedCredential = await requestCredential(aliceSession, cTypes, owner)

      expect(isIRequestCredential(requestedCredential.message)).toBeTruthy()
      expect((requestedCredential.message.body as IRequestCredential).content.owner).toBe(owner)
    })

    it('should throw an error if session is missing receiverEncryptionKeyUri', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const invalidSession = { ...aliceSession, receiverEncryptionKeyUri: undefined }

      //@ts-ignore
      await expect(requestCredential(invalidSession, cTypes)).rejects.toThrowError()
    })

    it('Bob should be able to decrypt the message', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const { encryptedMessage } = await requestCredential(aliceSession, cTypes)
      expect(async () => await decrypt(encryptedMessage, bobDecryptCallback)).not.toThrowError()
    })

    it('submit credential', async () => {
      const cTypes = [{ cTypeHash }]
      const { encryptedMessage, message } = await requestCredential(aliceSession, cTypes)

      const response = await submitCredential([credential], encryptedMessage, bobSession)

      const decryptedMessage = await decrypt(response, aliceDecryptCallback)

      expect(decryptedMessage.inReplyTo).toBe(message.messageId)
      expect(isSubmitCredential(decryptedMessage)).toBeTruthy()
      const body = decryptedMessage.body as ISubmitCredential
      expect(body.content[0].claim.cTypeHash).toBe(cTypeHash)
    })

    it('submit credential with wrong ctype hash', async () => {
      const claim = credential.claim
      const invalidClaim = { ...claim, cTypeHash: Crypto.hashStr('0x123456789') }
      const invalidCredential = Credential.fromClaim(invalidClaim)

      const cTypes = [{ cTypeHash: cTypeHash }]
      const { encryptedMessage } = await requestCredential(aliceSession, cTypes)

      await expect(submitCredential([invalidCredential], encryptedMessage, bobSession)).rejects.toThrowError()
    })

    it('submit credential with wrong owner', async () => {
      const claim = credential.claim
      const invalidClaim = { ...claim, cTypeHash: Crypto.hashStr('0x123456789') }
      const invalidCredential = Credential.fromClaim(invalidClaim)

      const cTypes = [{ cTypeHash: cTypeHash }]
      const { encryptedMessage } = await requestCredential(aliceSession, cTypes, bobFullDid.uri)

      await expect(submitCredential([invalidCredential], encryptedMessage, bobSession)).rejects.toThrowError()
    })

    it('Alice should be able to decrypt the message', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const { encryptedMessage } = await requestCredential(aliceSession, cTypes)

      const credentialMessage = await submitCredential([credential], encryptedMessage, bobSession)

      expect(async () => await decrypt(credentialMessage, aliceDecryptCallback)).not.toThrowError()
    })

    it('verify submitted Credential', async () => {
      const cTypes = [{ cTypeHash: cTypeHash }]
      const requestMessage = await requestCredential(aliceSession, cTypes)
      const responseMessage = await submitCredential([credential], requestMessage.encryptedMessage, bobSession)

      await expect(
        verifySubmittedCredentialMessage(responseMessage, aliceSession, requestMessage)
      ).resolves.not.toThrowError()
    })
  })
})
