import { DidResolveKey, IAttestation, KiltKeyringPair } from '@kiltprotocol/types'
import { Attestation, Did, ConfigService } from '@kiltprotocol/sdk-js'

import {
  IConfirmPaymentContent,
  IEncryptedMessage,
  IMessageWorkflow,
  IRequestPayment,
  ISession,
  ISubmitAttestation,
  ISubmitTerms,
  ITerms,
} from '../../../types/index.js'
import { isIConfirmPayment, isIRequestPayment, isRequestAttestation } from '../../../utils/index.js'
import { fromBody } from '../../utils.js'
import { decrypt, encrypt } from '../../MessageEnvelope.js'
import { assertKnownMessage } from '../../CredentialApiMessageType.js'
import { verifyQuoteAgreement } from '../../../quote/index.js'
import { isNumber } from '@polkadot/util'
import { encodeAddress } from '@polkadot/keyring'


async function checkAmountAndReceipientInTx() {

}

/**
 * Submits terms of a message workflow using encryption.
 *
 * @param content - The content of the terms to be submitted.
 * @param session - An object containing session information.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Only used for testing
 * @returns A promise that resolves to an object containing the encrypted message and the original message.
 */
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

/**
 * Requests payment and generates a response message using encryption.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param message - The previous message from the requester in the claim workflow
 * @param session - An object containing session information.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Only used for testing.
 * @throws Error if the decrypted message is not a request attestation message.
 * @throws Error if the message IDs do not match.
 * @returns A promise that resolves to an object containing the encrypted response message and the response message itself.
 */
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
    throw new Error('Wrong message. Expected request attestation message')
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

/**
 * Validates a confirmed payment based on the encrypted message, original message, and payment details.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param message - The previous message from the message workflow.
 * @param session - An object containing session information.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param recipient - The recipient's address for the payment. normaly the reuquester.
 * @param amount - The payment amount.
 * @throws Error if the decrypted message is not a confirm payment message.
 * @throws Error if the original message is not a request payment message.
 * @throws Error if the message IDs do not match.
 * @throws Error if claim hashes do not match.
 * @throws Error if the transaction does not exist.
 * @throws Error if recipient or amount in the transaction are incorrect.
 * @throws Error if the transaction was not successful.
 */
export async function validateConfirmedPayment(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { decryptCallback }: ISession,
  recipient: KiltKeyringPair['address'],
  amount: number
) {
  const decryptedMessage = await decrypt(encryptedMessage, decryptCallback)

  if (!isIConfirmPayment(decryptedMessage)) {
    throw new Error('Wrong message. Expected confirm payment message')
  }

  if (!isIRequestPayment(message)) {
    throw new Error('Wrong message. Expected request payment message')
  }

  const { inReplyTo, body } = decryptedMessage
  const { messageId } = message

  if (messageId !== inReplyTo) {
    throw new Error('Message Ids do not match')
  }

  if (message.body.content.claimHash !== body.content.claimHash) {
    throw new Error('Claim hashes do not match')
  }

  await validateTx(body.content, recipient, amount)
}

/**
 * Validates a transaction by checking its details and success status.
 * @param content - The content of the confirmed payment message.
 * @param recipient - The recipient's address for the payment.
 * @param amount - The payment amount.
 * @throws Error if the transaction does not exist.
 * @throws Error if recipient or amount in the transaction are incorrect.
 * @throws Error if the transaction was not successful.
 */
async function validateTx(
  { blockHash, txHash }: IConfirmPaymentContent,
  recipient: KiltKeyringPair['address'],
  amount: number
) {
  const api = ConfigService.get('api')
  const signedBlock = await api.rpc.chain.getBlock(blockHash)

  const signedBlockHash = signedBlock.block.header.hash
  const apiAt = await api.at(signedBlockHash)
  const allRecords = await apiAt.query.system.events()
  allRecords[0].phase

  const txIndex = signedBlock.block.extrinsics.findIndex(({ hash }) => hash.toHex() === txHash)

  if (txIndex === -1) {
    throw new Error('Tx does not exists')
  }

  // first: filter out all transfer records.
  const filteredRecords = allRecords.filter(({ phase }) => phase.isApplyExtrinsic && phase.asApplyExtrinsic.eq(txIndex))
  const transferRecord = filteredRecords.filter(({ event }) => api.events.balances.Transfer.is(event))

  // check if there is one transaction with the right amount to the right account
  transferRecord.map(({ event }) => {
    const transferredAmount = event.data.at(2)?.toPrimitive()
    const destination = encodeAddress(event.data.at(1)?.toPrimitive() as string)

    if (destination !== recipient) {
      throw new Error(`Wrong recipient in tx. Destination in tx: ${destination}, Target recipient: ${recipient}`)
    }

    if (!isNumber(transferredAmount) || transferredAmount < amount) {
      throw new Error(`Wrong amount in tx. Expected amount: ${transferredAmount}, Requested Amount: ${amount}`)
    }
  })

  // check now if tx was successfull
  const countSuccessfulTx = filteredRecords
    .filter(({ event }) => api.events.system.ExtrinsicSuccess.is(event)).length

  if (countSuccessfulTx === 0) {
    throw new Error('Tx was not successful')
  }
}

/**
 * Submits an attestation as a response using encryption.
 * @param attestation - The attestation to be submitted.
 * @param encryptedMessage - The encrypted message received as part of the message workflow.
 * @param message - The previous message from the message workflow.
 * @param session - An object containing session information.
 * @param session.receiverEncryptionKeyUri - The URI of the receiver's encryption key.
 * @param session.senderEncryptionKeyUri - The URI of the sender's encryption key.
 * @param session.encryptCallback - A callback function used for encryption.
 * @param session.decryptCallback - A callback function used for decryption.
 * @param options - Additional options for the function.
 * @param options.resolveKey - A function for resolving keys. (Optional) Should only be used for testing
 * @throws Error if the decrypted message is not a request attestation message.
 * @throws Error if the message IDs do not match.
 * @throws Error if the attestation is in the wrong format.
 * @throws Error if the attestation verification against the credential fails.
 * @returns A promise that resolves to an object containing the encrypted response message and the response message itself.
 */
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

  if (!isRequestAttestation(decryptedMessage)) {
    throw new Error('Wrong message. Expected request attestation message')
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
