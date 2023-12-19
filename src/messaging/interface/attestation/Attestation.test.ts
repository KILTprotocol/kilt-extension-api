/**
 * Copyright (c) 2018-2023, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

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
  ConfigService,
  ChainHelpers,
  Blockchain,
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
  validateConfirmedPayment,
} from '.'
import {
  isIConfirmPayment,
  isIRequestPayment,
  isRequestAttestation,
  isSubmitAttestation,
  isSubmitTerms,
} from '../../../utils'
import { decrypt } from '../../MessageEnvelope'
import { verifyAttesterSignedQuote, verifyQuoteAgreement } from '../../../quote'

describe('Attestation', () => {
  //Alice
  let aliceAccount: KiltKeyringPair
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSignCallback
  let aliceSignAssertion: KeyToolSignCallback
  let aliceDecryptCallback: DecryptCallback
  let aliceEncryptCallback: EncryptCallback
  let aliceMnemonic: string

  //Bob
  let bobAccount: KiltKeyringPair
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

  //Misc
  const COST = 100_000

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
    const keyPairsAlice = await keypairs(aliceMnemonic)
    aliceEncryptCallback = makeEncryptCallback(keyPairsAlice.keyAgreement)(aliceFullDid)
    aliceDecryptCallback = makeDecryptCallback(keyPairsAlice.keyAgreement)
    aliceSign = makeSignCallback(keyPairsAlice.authentication)
    aliceSignAssertion = makeSignCallback(keyPairsAlice.assertionMethod)

    //setup bob
    const bobMnemonic = mnemonicGenerate()
    bobAccount = new Keyring({}).addFromMnemonic(bobMnemonic) as KiltKeyringPair
    //give bob 10 KILT
    await fundAccount(bobAccount.address, new BN('10000000000000000'))
    bobFullDid = await generateDid(bobAccount, bobMnemonic)
    const keyPairsBob = await keypairs(bobMnemonic)
    bobEncryptCallback = makeEncryptCallback(keyPairsBob.keyAgreement)(bobFullDid)
    bobDecryptCallback = makeDecryptCallback(keyPairsBob.keyAgreement)
    bobSign = makeSignCallback(keyPairsBob.authentication)

    //sessions
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

    expect(isSubmitTerms(message)).toBe(true)

    // Bob should be able to decrypt the message
    await expect(decrypt(encryptedMessage, bobDecryptCallback)).resolves.not.toThrowError()

    const messageBody = message.body as ISubmitTerms
    expect(messageBody.content.quote).toBeDefined()

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    await expect(verifyAttesterSignedQuote(messageBody.content.quote!)).resolves.not.toThrowError()
  })
  it('requests credential', async () => {
    const credential = Credential.fromClaim(claim)

    const { encryptedMessage: requestMessageEncrypted, message: requestMessage } = await submitTerms(
      submitTermsContent,
      aliceSession
    )

    const { encryptedMessage, message } = await requestAttestation(requestMessageEncrypted, credential, bobSession)

    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isRequestAttestation(message)).toBe(true)

    const messageBody = message.body as IRequestAttestation

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    await expect(verifyQuoteAgreement(messageBody.content.quote!)).resolves.not.toThrowError()

    // Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrowError()
  })

  it('requests credential without quote', async () => {
    const credential = Credential.fromClaim(claim)

    submitTermsContent.quote = undefined
    const { encryptedMessage: requestMessageEncrypted, message: requestMessage } = await submitTerms(
      submitTermsContent,
      aliceSession
    )

    const { encryptedMessage, message } = await requestAttestation(requestMessageEncrypted, credential, bobSession)

    expect(message.inReplyTo).toBe(requestMessage.messageId)
    expect(isRequestAttestation(message)).toBe(true)

    const messageBody = message.body as IRequestAttestation
    expect(messageBody.content.quote).toBeUndefined()

    // Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrowError()
  })

  it('requests payment', async () => {
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
    expect(isIRequestPayment(message)).toBe(true)

    const messageBody = message.body as IRequestPayment
    const messageBodyRequest = requestMessage.body as IRequestAttestation

    expect(messageBody.content.claimHash).toBe(messageBodyRequest.content.credential.rootHash)

    // Bob should be able to decrypt the message
    await expect(decrypt(encryptedMessage, bobDecryptCallback)).resolves.not.toThrowError()
  })

  it('confirms payment', async () => {
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
    expect(isIConfirmPayment(message)).toBe(true)

    // Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrowError()
  })

  it('validate confirmed payment message', async () => {
    const credential = Credential.fromClaim(claim)
    const requestTerms = await submitTerms(submitTermsContent, aliceSession)
    const requestAttestationMessages = await requestAttestation(requestTerms.encryptedMessage, credential, bobSession)
    const requestPaymentMessages = await requestPayment(
      requestAttestationMessages.encryptedMessage,
      requestTerms,
      aliceSession
    )

    const api = ConfigService.get('api')

    const txTransfer = api.tx.balances.transfer(aliceAccount.address, COST)

    const finalizedTx = await ChainHelpers.Blockchain.signAndSubmitTx(txTransfer, bobAccount, {
      resolveOn: Blockchain.IS_FINALIZED,
    })

    const paymentConfirmation: IConfirmPaymentContent = {
      blockHash: finalizedTx.status.asFinalized.toString(),
      claimHash: credential.rootHash,
      txHash: finalizedTx.txHash.toString(),
    }

    const { encryptedMessage } = await confirmPayment(
      requestPaymentMessages.encryptedMessage,
      paymentConfirmation,
      requestAttestationMessages,
      bobSession
    )

    // Alice should be able to decrypt the message
    await expect(decrypt(encryptedMessage, aliceDecryptCallback)).resolves.not.toThrowError()

    await expect(
      validateConfirmedPayment(encryptedMessage, requestPaymentMessages, aliceSession, aliceAccount.address, COST)
    ).resolves.not.toThrowError()
  })

  it('submits attestation', async () => {
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
    expect(isSubmitAttestation(message)).toBe(true)

    // Bob should be able to decrypt the message
    await expect(decrypt(encryptedMessage, bobDecryptCallback)).resolves.not.toThrowError()
  })

  it('receives attestation', async () => {
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

    // Anchor attestation to the blockchain
    await createCtype(aliceFullDid.uri, aliceAccount, aliceMnemonic, testCType)
    await createAttestation(
      aliceAccount,
      aliceFullDid.uri,
      aliceSignAssertion(aliceFullDid),
      credential.rootHash,
      claim.cTypeHash
    )

    // Send anchored attestation
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
