import { DidResolveKey, ICredential, IEncryptedMessage } from '@kiltprotocol/types'
import { Attestation, Credential, Did } from '@kiltprotocol/sdk-js'

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
import { decrypt, encrypt } from '../../MessageEnvelope.'
import { assertKnownMessage } from '../../CredentialApiMessageType'
import { isIRequestPayment, isRequestAttestation, isSubmitAttestation, isSubmitTerms } from '../../../utils'
import { fromBody } from '../../utils'
import { createQuoteAgreement, verifyAttesterSignedQuote } from '../../../quote'

export async function requestAttestation(
  encryptedMessage: IEncryptedMessage,
  credential: ICredential,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback, signCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })

  if (!isSubmitTerms(decryptedMessage)) {
    throw new Error('Wrong message. Expected submit terms message')
  }

  Credential.verifyWellFormed(credential)

  const { claim: requestClaim, rootHash } = credential
  const { claim: proposedClaim, quote: attesterQuote } = decryptedMessage.body.content

  if (JSON.stringify(proposedClaim) !== JSON.stringify(requestClaim)) {
    throw new Error('Claims do not match')
  }

  let quote: IQuoteAgreement | undefined = undefined

  const { did: sender } = Did.parse(senderEncryptionKeyUri)
  const { did: receiver } = Did.parse(receiverEncryptionKeyUri)

  if (attesterQuote) {
    verifyAttesterSignedQuote(attesterQuote, { didResolveKey: resolveKey })
    quote = await createQuoteAgreement(attesterQuote, rootHash, signCallback, sender, {
      didResolveKey: resolveKey,
    })
  }

  const body: IRequestAttestation = {
    content: { credential, quote },
    type: 'request-attestation',
  }

  const message = fromBody(body, sender, receiver)
  message.inReplyTo = decryptedMessage.messageId
  return {
    encryptedMessage: await encrypt(message, encryptCallback, receiverEncryptionKeyUri, { resolveKey }),
    message,
  }
}

export async function confirmPayment(
  encryptedMessage: IEncryptedMessage,
  paymentConfirmation: IConfirmPaymentContent,
  { message }: IMessageWorkflow,
  { decryptCallback, senderEncryptionKeyUri, receiverEncryptionKeyUri, encryptCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })

  if (!isIRequestPayment(decryptedMessage)) {
    throw new Error('Wrong message. Expected request payment message')
  }

  if (decryptedMessage.inReplyTo !== message.messageId) {
    throw new Error('wrong reply. Decrypted message points to wrong previous message')
  }

  const body: IConfirmPayment = {
    type: 'confirm-payment',
    content: paymentConfirmation,
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

export async function receiveAttestation(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { decryptCallback }: ISession,
  {
    resolveKey = Did.resolveKey,
  }: {
    resolveKey?: DidResolveKey
  } = {}
): Promise<IMessage<ISubmitAttestation>> {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback, { resolveKey })
  if (!isSubmitAttestation(decryptedMessage)) {
    throw new Error('Wrong message. Expected submit attestation message')
  }

  if (!isRequestAttestation(message)) {
    throw new Error('Wrong Message. Expected request attestation message')
  }

  if (decryptedMessage.inReplyTo !== message.messageId) {
    throw new Error('wrong reply. Decrypted message points to wrong previous message')
  }

  const { credential } = message.body.content

  const { attestation } = decryptedMessage.body.content

  Attestation.verifyAgainstCredential(attestation, credential)

  Credential.verifyAttested(credential)

  return decryptedMessage
}
