import { DidResolveKey, IAttestation } from '@kiltprotocol/types'
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
} from '../../../types'
import { isIConfirmPayment, isIRequestPayment, isRequestAttestation } from '../../../utils'
import { fromBody } from '../../utils'
import { decrypt, encrypt } from '../../MessageEnvelope.'
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

export async function validateConfirmedPayment(
  encryptedMessage: IEncryptedMessage,
  { message }: IMessageWorkflow,
  { decryptCallback }: ISession
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

  await validateTx(body.content)
}

async function validateTx({ blockHash, txHash }: IConfirmPaymentContent) {
  const api = ConfigService.get('api')
  const signedBlock = await api.rpc.chain.getBlock(blockHash)

  const apiAt = await api.at(signedBlock.block.header.hash)
  const allRecords = await apiAt.query.system.events()
  allRecords[0].phase

  const txIndex = signedBlock.block.extrinsics.findIndex(({ hash }) => {
    hash.toHex() === txHash
  })

  if (txIndex === -1) {
    throw new Error('Tx does not exists')
  }

  allRecords
    .filter(({ phase }) => phase.isApplyExtrinsic && phase.asApplyExtrinsic.eq(txIndex))
    .forEach(({ event }) => {
      if (api.events.system.ExtrinsicSuccess.is(event)) {
        //TODO check if tx was transfer and that the ammount was the right.
        const [dispatchInfo] = event.data

        console.log('ich bin hier')
        console.log(event.data)
        return
      }
      throw new Error('Tx was not successful')
    })
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
