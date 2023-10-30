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
import { decrypt, encrypt } from '../../MessageEnvelope'
import { isIRequestPayment, isRequestAttestation, isSubmitAttestation, isSubmitTerms } from '../../../utils'
import { fromBody } from '../../utils'
import { createQuoteAgreement, verifyAttesterSignedQuote } from '../../../quote'

/**
 * Requests an attestation based on a received encrypted message and a credential.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param credential - The credential for which the attestation is requested.
 * @param session - An object containing session information.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param session.signCallback - A callback function used for signing.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Only used for tests
 * @throws Error if the decrypted message is not a submit terms message.
 * @throws Error if the claims in the credential and proposed claim do not match.
 * @throws Error if attester's quote verification fails.
 * @returns A promise that resolves to an object containing the encrypted response message and the response message itself.
 */
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

/**
 * Confirms a payment and generates a response message using encryption.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param paymentConfirmation - The content confirming the payment.
 * @param message - The previous message from the message workflow.
 * @param session - An object containing session information.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Only used for tests
 * @throws Error if the decrypted message is not a request payment message.
 * @throws Error if the decrypted message points to the wrong previous message.
 * @returns A promise that resolves to an object containing the encrypted response message and the response message itself.
 */
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

/**
 * Receives an attestation, verifies its validity, and returns the decrypted message.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param message - The previous message from the message workflow.
 * @param session - An object containing session information.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Only used for tests
 * @throws Error if the decrypted message is not a submit attestation message.
 * @throws Error if the original message is not a request attestation message.
 * @throws Error if the decrypted message points to the wrong previous message.
 * @throws Error if attestation verification against the credential fails.
 * @throws Error if credential attestation verification fails.
 * @returns A promise that resolves to the decrypted message containing the submitted attestation.
 */
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

  await Credential.verifyAttested(credential)

  return decryptedMessage
}
