import { DidResolveKey, IAttestation } from '@kiltprotocol/types'
import { Attestation, Did } from '@kiltprotocol/sdk-js'

import {
  IEncryptedMessage,
  IMessageWorkflow,
  IRequestPayment,
  ISession,
  ISubmitAttestation,
  ISubmitTerms,
  ITerms,
} from '../../../types'
import { isIConfirmPayment, isRequestAttestation } from '../../../utils'
import { fromBody } from '../../utils'
import { decrypt, encrypt } from '../../Crypto'
import { assertKnownMessage } from '../../CredentialApiMessageType'
import { verifyQuoteAgreement } from '../../../quote'

export async function submitTerms(
  content: ITerms,
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IMessageWorkflow> {
  const body: ISubmitTerms = {
    content,
    type: 'submit-terms',
  }

  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)

  const message = fromBody(body, sender, receiver)
  return {
    encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri, { resolveKey }),
    message,
  }
}

export async function requestPayment(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback, decryptCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })
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

  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)
  const response = fromBody(body, sender, receiver)
  response.inReplyTo = decryptedMessage.messageId
  return {
    encryptedMessage: await encrypt(response, encryptCallback, receiverEncryptionKeyUri, { resolveKey }),
    message: response,
  }
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

  if (!isIConfirmPayment(decryptedMessage)) {
    throw new Error('Wrong message')
  }

  const { inReplyTo, body } = decryptedMessage
  const { messageId } = message

  //TODO check if blockHash is on blockchain and txHash is there 2.
  const { blockHash, claimHash, txHash } = body.content

  if (messageId !== inReplyTo) {
    throw new Error('Message Ids do not match')
  }
}

export async function submitAttestation(
  attestation: IAttestation,
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { receiverEncryptionKeyUri, senderEncryptionKeyUri, encryptCallback, decryptCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IMessageWorkflow> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })
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

  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)

  const responseBody: ISubmitAttestation = {
    content: {
      attestation,
    },
    type: 'submit-attestation',
  }

  const response = fromBody(responseBody, sender, receiver)
  response.inReplyTo = decryptedMessage.messageId
  return {
    encryptedMessage: await encrypt(response, encryptCallback, receiverEncryptionKeyUri, { resolveKey }),
    message: response,
  }
}
