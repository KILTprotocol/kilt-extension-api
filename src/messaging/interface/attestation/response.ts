import { ICredential, IEncryptedMessage } from '@kiltprotocol/types'
import { Credential } from '@kiltprotocol/sdk-js'

import {
  IConfirmPayment,
  IConfirmPaymentContent,
  IMessage,
  IMessageWorkflow,
  IQuoteAgreement,
  IRequestAttestation,
  ISession,
  ISubmitAttestation,
} from '../../../types'
import { decrypt, encrypt } from '../../Crypto'
import { assertKnownMessage } from '../../CredentialApiMessageType'
import { getDidUriFromDidResourceUri, isIRequestPayment, isSubmitAttestation, isSubmitTerms } from '../../../utils'
import { fromBody } from '../../utils'
import { verifyAttesterSignedQuote, createQuoteAgreement } from '../../../quote'

export async function requestAttestation(
  encryptedMessage: IEncryptedMessage,
  credential: ICredential,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback, signCallback }: ISession
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)
  if (!isSubmitTerms(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  Credential.verifyCredential(credential)

  const { claim: requestClaim } = credential
  const { claim: proposedClaim, quote: attesterQuote } = decryptedMessage.body.content

  if (JSON.stringify(proposedClaim) !== JSON.stringify(requestClaim)) {
    throw new Error('Claims do not match')
  }

  let quote: IQuoteAgreement | undefined = undefined

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)

  if (attesterQuote) {
    verifyAttesterSignedQuote(attesterQuote)
    quote = await createQuoteAgreement(attesterQuote, proposedClaim.cTypeHash, signCallback, sender)
  }

  const body: IRequestAttestation = {
    content: { credential, quote },
    type: 'request-attestation',
  }

  const message = fromBody(body, sender, receiver)
  message.inReplyTo = decryptedMessage.messageId
  return { encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri), message }
}

export async function confirmPayment(
  encryptedMessage: IEncryptedMessage,
  paymentConfirmation: IConfirmPaymentContent,
  { message }: IMessageWorkflow,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback }: ISession
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)
  if (!isIRequestPayment(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  if (message.messageId === decryptedMessage.inReplyTo) {
    throw new Error('wrong response')
  }

  const body: IConfirmPayment = {
    type: 'confirm-payment',
    content: paymentConfirmation,
  }

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)

  const response = fromBody(body, sender, receiver)
  response.inReplyTo = decryptedMessage.messageId
  return { encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri), message }
}

export async function receiveAttestation(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { decryptCallback }: ISession
): Promise<IMessage<ISubmitAttestation>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)
  if (!isSubmitAttestation(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  if (message.messageId === decryptedMessage.inReplyTo) {
    throw new Error('wrong response')
  }

  return decryptedMessage
}
