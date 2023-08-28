/* eslint-disable @typescript-eslint/ban-ts-comment */
import {
  CType,
  Claim,
  DidDocument,
  ICType,
  IClaim,
  Credential,
  Quote,
  IConfirmPaymentContent,
  IAttestation,
  connect,
  KiltKeyringPair,
  DecryptCallback,
  EncryptCallback,
} from '@kiltprotocol/sdk-js'
import { BN } from '@polkadot/util'
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
import { IRequestAttestation, IRequestPayment, ISession, ISessionRequest, ISubmitTerms, ITerms } from '../../../types'
import {
  confirmPayment,
  receiveAttestation,
  requestAttestation,
  requestPayment,
  submitAttestation,
  submitTerms,
} from '.'
import {
  isIConfirmPayment,
  isIRequestPayment,
  isRequestAttestation,
  isSubmitAttestation,
  isSubmitTerms,
} from '../../../utils'
import { decrypt } from '../../MessageEnvelope.'
import { verifyAttesterSignedQuote, verifyQuoteAgreement } from '../../../quote'

describe('Verifier', () => {
  //Alice
  let aliceAccount: KiltKeyringPair
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSignCallback
  let aliceSignAssertion: KeyToolSignCallback
  let aliceDecryptCallback: DecryptCallback
  let aliceEncryptCallback: EncryptCallback
  let aliceMnemonic: string

  //Bob
  let bobFullDid: DidDocument
  let bobSign: KeyToolSignCallback
  let bobDecryptCallback: DecryptCallback
  let bobEncryptCallback: EncryptCallback

  //session
  let sessionRequest: ISessionRequest
  let aliceSession: ISession
  let bobSession: ISession

  //Terms
  let claim: IClaim
  let claimContents: IClaim['contents']
  let testCType: ICType
  let submitTermsContent: ITerms

  beforeAll(async () => {
    const address = await startContainer()
    await connect(address)
  }, 20_000)

  beforeAll(async () => {
    //setup alice
    aliceMnemonic = mnemonicGenerate()
    aliceAccount = new Keyring({}).addFromMnemonic(aliceMnemonic) as KiltKeyringPair
    //give alice 10 KILT
    await fundAccount(aliceAccount.address, new BN('10000000000000000'))
    aliceFullDid = await generateDid(aliceAccount, aliceMnemonic)
    const keyPairsAlice = await keypairs(aliceAccount, aliceMnemonic)
    aliceEncryptCallback = makeEncryptCallback(keyPairsAlice.keyAgreement)(aliceFullDid)
    aliceDecryptCallback = makeDecryptCallback(keyPairsAlice.keyAgreement)
    aliceSign = makeSignCallback(keyPairsAlice.authentication)
    aliceSignAssertion = makeSignCallback(keyPairsAlice.assertion)

    //setup bob
    const bobMnemonic = mnemonicGenerate()
    const bobAccount = new Keyring({}).addFromMnemonic(bobMnemonic) as KiltKeyringPair
    //give bob 10 KILT
    await fundAccount(bobAccount.address, new BN('10000000000000000'))
    bobFullDid = await generateDid(bobAccount, bobMnemonic)
    const keyPairsBob = await keypairs(bobAccount, bobMnemonic)
    bobEncryptCallback = makeEncryptCallback(keyPairsBob.keyAgreement)(bobFullDid)
    bobDecryptCallback = makeDecryptCallback(keyPairsBob.keyAgreement)
    bobSign = makeSignCallback(keyPairsBob.authentication)

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

    testCType = CType.fromProperties('testCtype', {
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
  }, 20_000)

  it('submits terms successfully', async () => {
    const { message, encryptedMessage } = await submitTerms(submitTermsContent, aliceSession)
    expect(isSubmitTerms(message)).toBeTruthy()

    // Bob should be able to decrypt the message
    await expect(decrypt(encryptedMessage, bobDecryptCallback)).resolves.not.toThrowError()

    const messageBody = message.body as ISubmitTerms
    expect(messageBody.content.quote).toBeDefined()
    await expect(
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      verifyAttesterSignedQuote(messageBody.content.quote!)
    ).resolves.not.toThrowError()
  })

  it('request credential', async () => {
    const credential = Credential.fromClaim(claim)

    const { encryptedMessage: requestMessageEncrypted, message: requestMessage } = await submitTerms(
      submitTermsContent,
      aliceSession
    )
    const { encryptedMessage, message } = await requestAttestation(requestMessageEncrypted, credential, bobSession)
    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isRequestAttestation(message)).toBeTruthy()
    const messageBody = message.body as IRequestAttestation
    //   eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(verifyQuoteAgreement(messageBody.content.quote!))

    //Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrow()
  })

  it('request credential without quote', async () => {
    const credential = Credential.fromClaim(claim)

    submitTermsContent.quote = undefined
    const { encryptedMessage: requestMessageEncrypted, message: requestMessage } = await submitTerms(
      submitTermsContent,
      aliceSession
    )
    const { encryptedMessage, message } = await requestAttestation(requestMessageEncrypted, credential, bobSession)
    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isRequestAttestation(message)).toBeTruthy()
    const messageBody = message.body as IRequestAttestation
    //   eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    expect(messageBody.content.quote!).toBeUndefined()

    //Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrow()
  })

  it('request payment', async () => {
    const credential = Credential.fromClaim(claim)
    const requestTerms = await submitTerms(submitTermsContent, aliceSession)
    const { encryptedMessage: encryptedRequestAttestationMessage, message: requestMessage } = await requestAttestation(
      requestTerms.encryptedMessage,
      credential,
      bobSession
    )

    const { encryptedMessage, message } = await requestPayment(
      encryptedRequestAttestationMessage,
      requestTerms,
      aliceSession
    )

    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isIRequestPayment(message)).toBeTruthy()

    const messageBody = message.body as IRequestPayment
    const messageBodyRequest = requestMessage.body as IRequestAttestation

    expect(messageBody.content.claimHash).toBe(messageBodyRequest.content.credential.rootHash)

    //Bob should be able to decrypt the message
    await expect(decrypt(encryptedMessage, bobDecryptCallback)).resolves.not.toThrow()
  })

  it('confirm payment', async () => {
    const credential = Credential.fromClaim(claim)
    const requestTerms = await submitTerms(submitTermsContent, aliceSession)
    const requestAttestationMessages = await requestAttestation(requestTerms.encryptedMessage, credential, bobSession)

    const requestPaymentMessages = await requestPayment(
      requestAttestationMessages.encryptedMessage,
      requestTerms,
      aliceSession
    )
    const paymentConfirmation: IConfirmPaymentContent = {
      blockHash: '123456',
      claimHash: '123456',
      txHash: '123456',
    }

    const { encryptedMessage, message } = await confirmPayment(
      requestPaymentMessages.encryptedMessage,
      paymentConfirmation,
      requestAttestationMessages,
      bobSession
    )

    expect(message.inReplyTo).toBe(requestPaymentMessages.message.messageId)
    expect(isIConfirmPayment(message)).toBeTruthy()

    //Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrow()
  })

  it('submit attestation', async () => {
    const credential = Credential.fromClaim(claim)

    const attestation: IAttestation = {
      delegationId: null,
      claimHash: credential.rootHash,
      cTypeHash: claim.cTypeHash,
      owner: bobFullDid.uri,
      revoked: false,
    }

    const requestTerms = await submitTerms(submitTermsContent, aliceSession)

    const requestAttestationMessages = await requestAttestation(requestTerms.encryptedMessage, credential, bobSession)

    const { encryptedMessage, message } = await submitAttestation(
      attestation,
      requestAttestationMessages.encryptedMessage,
      requestTerms,
      aliceSession
    )

    expect(message.inReplyTo).toBe(requestAttestationMessages.message.messageId)
    expect(isSubmitAttestation(message)).toBeTruthy()

    //Bob should be able to decrypt the message
    await expect(decrypt(encryptedMessage, bobDecryptCallback)).resolves.not.toThrow()
  })

  it('receive attestation', async () => {
    const credential = Credential.fromClaim(claim)

    const attestation: IAttestation = {
      delegationId: null,
      claimHash: credential.rootHash,
      cTypeHash: claim.cTypeHash,
      owner: bobFullDid.uri,
      revoked: false,
    }

    const requestTerms = await submitTerms(submitTermsContent, aliceSession)

    const requestAttestationMessages = await requestAttestation(requestTerms.encryptedMessage, credential, bobSession)

    // anchor attestation to blockchain
    await createCtype(aliceFullDid.uri, aliceAccount, aliceMnemonic, testCType)
    await createAttestation(
      aliceAccount,
      aliceFullDid.uri,
      aliceSignAssertion(aliceFullDid),
      credential.rootHash,
      claim.cTypeHash
    )

    //send anchored attestation

    const submitAttestationMessage = await submitAttestation(
      attestation,
      requestAttestationMessages.encryptedMessage,
      requestTerms,
      aliceSession
    )

    await expect(
      receiveAttestation(submitAttestationMessage.encryptedMessage, requestAttestationMessages, bobSession)
    ).resolves.not.toThrowError()
  })
})
