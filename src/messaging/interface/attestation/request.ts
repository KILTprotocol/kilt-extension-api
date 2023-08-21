import { IAttestation } from '@kiltprotocol/types'
import { Attestation } from '@kiltprotocol/sdk-js'

import {
  IEncryptedMessage,
  IMessageWorkflow,
  IRequestPayment,
  ISession,
  ISubmitAttestation,
  ISubmitTerms,
  ITerms,
} from '../../../types'
import { getDidUriFromDidResourceUri, isIConfirmPayment, isRequestAttestation } from '../../../utils'
import { fromBody } from '../../utils'
import { decrypt, encrypt } from '../../Crypto'
import { assertKnownMessage } from 'message/index'
import { verifyQuoteAgreement } from 'src/quote'

export async function submitTerms(
  content: ITerms,
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession
): Promise<IMessageWorkflow> {
  const body: ISubmitTerms = {
    content,
    type: 'submit-terms',
  }

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver)
  return { encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri), message }
}

export async function requestPayment(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback, decryptCallback }: ISession
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)
  if (!isRequestAttestation(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  const { inReplyTo } = decryptedMessage
  const { messageId } = message
  const { rootHash } = decryptedMessage.body.content.credential

  if (messageId !== inReplyTo) {
    throw new Error('Message Ids do not match')
  }

  const body: IRequestPayment = {
    type: 'request-payment',
    content: { claimHash: rootHash },
  }

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)
  const response = fromBody(body, sender, receiver)
  response.inReplyTo = decryptedMessage.messageId
  return { encryptedMessage: await encrypt(response, encryptCallback, receiverEncryptionKeyUri), message: response }
}

export async function validateConfirmedPayment(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { decryptCallback }: ISession
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  if (!decryptedMessage) {
    throw new Error('Wrong message')
  }
  assertKnownMessage(decryptedMessage)

  if (!isIConfirmPayment(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  const { inReplyTo } = decryptedMessage
  const { messageId } = message

  if (messageId !== inReplyTo) {
    throw new Error('Message Ids do not match')
  }
}

export async function submitAttestation(
  attestation: IAttestation,
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback, decryptCallback }: ISession
): Promise<IMessageWorkflow> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)
  assertKnownMessage(decryptedMessage)
  if (!isRequestAttestation(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  const { inReplyTo } = decryptedMessage
  const { messageId } = message
  const { credential, quote } = decryptedMessage.body.content

  if (messageId !== inReplyTo) {
    throw new Error('Message Ids do not match')
  }

  Attestation.verifyDataStructure(attestation)
  if (!Attestation.isIAttestation(attestation)) {
    throw new Error('Attestation is wrong format')
  }

  Attestation.verifyAgainstCredential(attestation, credential)

  if (quote) {
    verifyQuoteAgreement(quote)
  }

  const sender = getDidUriFromDidResourceUri(senderEncryptionKeyUri)
  const receiver = getDidUriFromDidResourceUri(receiverEncryptionKeyUri)

  const responseBody: ISubmitAttestation = {
    content: {
      attestation,
    },
    type: 'submit-attestation',
  }

  const response = fromBody(responseBody, sender, receiver)
  response.inReplyTo = decryptedMessage.messageId
  return { encryptedMessage: await encrypt(response, encryptCallback, receiverEncryptionKeyUri), message: response }
}
