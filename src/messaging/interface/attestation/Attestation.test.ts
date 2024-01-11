/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/* eslint-disable @typescript-eslint/ban-ts-comment */
import { Blockchain } from '@kiltprotocol/chain-helpers'
import { CType } from '@kiltprotocol/credentials'
import { Claim, Credential } from '@kiltprotocol/legacy-credentials'
import { ConfigService, connect } from '@kiltprotocol/sdk-js'
import type { DidDocument, IAttestation, ICType, IClaim, KiltKeyringPair } from '@kiltprotocol/types'
import Keyring from '@polkadot/keyring'
import { BN } from '@polkadot/util'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import {
  confirmPayment,
  receiveAttestation,
  requestAttestation,
  requestPayment,
  submitAttestation,
  submitTerms,
  validateConfirmedPayment,
} from '.'
import { createAttesterSignedQuote, verifyAttesterSignedQuote, verifyQuoteAgreement } from '../../../quote'
import {
  KeyToolSigners,
  createAttestation,
  createCtype,
  fundAccount,
  generateDid,
  keypairs,
  makeDecryptCallback,
  makeDidSigners,
  makeEncryptCallback,
  startContainer,
} from '../../../tests'
import {
  DecryptCallback,
  EncryptCallback,
  IConfirmPaymentContent,
  IRequestAttestation,
  IRequestPayment,
  ISession,
  ISessionRequest,
  ISubmitTerms,
  ITerms,
} from '../../../types'
import {
  isIConfirmPayment,
  isIRequestPayment,
  isRequestAttestation,
  isSubmitAttestation,
  isSubmitTerms,
} from '../../../utils'
import { decrypt } from '../../MessageEnvelope'
import { receiveSessionRequest, requestSession, verifySession } from '../session'

describe('Attestation', () => {
  //Alice
  let aliceAccount: KiltKeyringPair
  let aliceFullDid: DidDocument
  let aliceSign: KeyToolSigners
  let aliceSignAssertion: KeyToolSigners
  let aliceDecryptCallback: DecryptCallback
  let aliceEncryptCallback: EncryptCallback
  let aliceMnemonic: string

  //Bob
  let bobAccount: KiltKeyringPair
  let bobFullDid: DidDocument
  let bobSign: KeyToolSigners
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
    aliceSign = makeDidSigners(keyPairsAlice.authentication)
    aliceSignAssertion = makeDidSigners(keyPairsAlice.assertionMethod)

    //setup bob
    const bobMnemonic = mnemonicGenerate()
    bobAccount = new Keyring({}).addFromMnemonic(bobMnemonic) as KiltKeyringPair
    //give bob 10 KILT
    await fundAccount(bobAccount.address, new BN('10000000000000000'))
    bobFullDid = await generateDid(bobAccount, bobMnemonic)
    const keyPairsBob = await keypairs(bobMnemonic)
    bobEncryptCallback = makeEncryptCallback(keyPairsBob.keyAgreement)(bobFullDid)
    bobDecryptCallback = makeDecryptCallback(keyPairsBob.keyAgreement)
    bobSign = makeDidSigners(keyPairsBob.authentication)

    //sessions
    sessionRequest = requestSession(aliceFullDid, 'MyApp')
    const { session, sessionResponse } = await receiveSessionRequest(
      bobFullDid,
      sessionRequest,
      bobEncryptCallback,
      bobDecryptCallback,
      await bobSign(bobFullDid)
    )
    bobSession = session

    aliceSession = await verifySession(
      sessionRequest,
      sessionResponse,
      aliceDecryptCallback,
      aliceEncryptCallback,
      await aliceSign(aliceFullDid)
    )

    testCType = CType.fromProperties('testCtype', {
      name: { type: 'string' },
    })

    claimContents = {
      name: 'Bob',
    }

    claim = Claim.fromCTypeAndClaimContents(testCType, claimContents, bobFullDid.id)

    const quoteData = {
      attesterDid: aliceFullDid.id,
      cTypeHash: claim.cTypeHash,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: new Date(2024, 8, 23).toISOString(),
    }
    // Quote signed by attester
    const quoteAttesterSigned = await createAttesterSignedQuote(quoteData, aliceSession['authenticationSigner'])

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

    const finalizedTx = await Blockchain.signAndSubmitTx(txTransfer, bobAccount, {
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
      owner: bobFullDid.id,
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
      owner: bobFullDid.id,
      revoked: false,
    }

    const requestTerms = await submitTerms(submitTermsContent, aliceSession)

    const requestAttestationMessages = await requestAttestation(requestTerms.encryptedMessage, credential, bobSession)

    // Anchor attestation to the blockchain
    await createCtype(aliceFullDid.id, aliceAccount, aliceMnemonic, testCType)
    await createAttestation(
      aliceAccount,
      aliceFullDid.id,
      await aliceSignAssertion(aliceFullDid),
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
