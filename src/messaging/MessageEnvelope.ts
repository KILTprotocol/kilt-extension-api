/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import type { DidUrl, VerificationMethod } from '@kiltprotocol/types'
import * as Did from '@kiltprotocol/did'
import * as MessageError from './Error.js'
import { hexToU8a, stringToU8a, u8aToHex, u8aToString } from '@polkadot/util'

import type {
  EncryptCallback,
  DecryptCallback,
  IEncryptedMessage,
  IEncryptedMessageContents,
  IMessage,
} from '../types/index.js'

/**
 * Checks if the message object is well-formed.
 *
 * @param message The message object.
 */
export function verifyMessageEnvelope(message: IMessage): void {
  const { messageId, createdAt, receiver, sender, receivedAt, inReplyTo } = message
  if (messageId !== undefined && typeof messageId !== 'string') {
    throw new TypeError('Message id is expected to be a string')
  }
  if (createdAt !== undefined && typeof createdAt !== 'number') {
    throw new TypeError('Created at is expected to be a number')
  }
  if (receivedAt !== undefined && typeof receivedAt !== 'number') {
    throw new TypeError('Received at is expected to be a number')
  }
  Did.validateDid(sender, 'Did')
  Did.validateDid(receiver, 'Did')
  if (inReplyTo && typeof inReplyTo !== 'string') {
    throw new TypeError('In reply to is expected to be a string')
  }
}

async function getPublicKeyForKeyAgreement(
  dereference: typeof Did.dereference,
  keyUrl: DidUrl
): Promise<{ publicKey: Uint8Array; controller: string }> {
  const { contentStream } = await dereference(keyUrl, { accept: 'application/did+json' })
  if ((contentStream as VerificationMethod)?.type !== 'Multikey') {
    throw new Error(`did url ${keyUrl} does not resolve to a Multikey verification key as expected`)
  }
  const verificationMethod = contentStream as VerificationMethod
  const { keyType, publicKey } = Did.multibaseKeyToDidKey(verificationMethod.publicKeyMultibase)
  if (keyType !== 'x25519') {
    throw new Error(`key type ${keyType} is not suitable for x25519 key agreement`)
  }
  return { publicKey, controller: verificationMethod.controller }
}

/**
 * Symmetrically decrypts the result of [[encrypt]].
 *
 * @param encrypted The encrypted message.
 * @param decryptCallback The callback to decrypt with the secret key.
 * @param decryptionOptions Options to perform the decryption operation.
 * @param decryptionOptions.dereferenceDidUrl The method to dereference the DID's key agreement key.
 * @returns The original [[Message]].
 */
export async function decrypt(
  encrypted: IEncryptedMessage,
  decryptCallback: DecryptCallback,
  {
    dereferenceDidUrl = Did.dereference,
  }: {
    dereferenceDidUrl?: typeof Did.dereference
  } = {}
): Promise<IMessage> {
  const { senderKeyUri, receiverKeyUri, ciphertext, nonce, receivedAt } = encrypted

  const { publicKey: peerPublicKey, controller } = await getPublicKeyForKeyAgreement(dereferenceDidUrl, senderKeyUri)

  const { fragment } = Did.parse(receiverKeyUri)
  if (!fragment) {
    throw new MessageError.DidError(`No fragment for the receiver key ID "${receiverKeyUri}"`)
  }

  let data: Uint8Array
  try {
    data = (
      await decryptCallback({
        peerPublicKey,
        data: hexToU8a(ciphertext),
        nonce: hexToU8a(nonce),
        keyUri: receiverKeyUri,
      })
    ).data
  } catch (cause) {
    throw new MessageError.DecodingMessageError(cause as string)
  }

  const decoded = u8aToString(data)

  const { body, createdAt, messageId, inReplyTo, references, sender, receiver } = JSON.parse(
    decoded
  ) as IEncryptedMessageContents
  const decrypted: IMessage = {
    receiver,
    sender,
    createdAt,
    body,
    messageId,
    receivedAt,
    inReplyTo,
    references,
  }

  verifyMessageEnvelope(decrypted)
  if (sender !== controller) {
    throw new MessageError.IdentityMismatchError(`Sender: ${sender}, found: ${controller}`)
  }

  return decrypted
}

/**
 * Encrypts the [[Message]] as a string.
 *
 * @param message The message to encrypt.
 * @param encryptCallback The callback to encrypt with the secret key.
 * @param receiverKeyUri The key URI of the receiver.
 * @param encryptionOptions Options to perform the encryption operation.
 * @param encryptionOptions.dereferenceDidUrl The DID key resolver to use.
 *
 * @returns The encrypted version of the original [[Message]], see [[IEncryptedMessage]].
 */
export async function encrypt(
  message: IMessage,
  encryptCallback: EncryptCallback,
  receiverKeyUri: DidUrl,
  {
    dereferenceDidUrl = Did.dereference,
  }: {
    dereferenceDidUrl?: typeof Did.dereference
  } = {}
): Promise<IEncryptedMessage> {
  verifyMessageEnvelope(message)
  const { publicKey: peerPublicKey, controller } = await getPublicKeyForKeyAgreement(dereferenceDidUrl, receiverKeyUri)
  if (message.receiver !== controller) {
    throw new MessageError.IdentityMismatchError('Message.recevier does not match controller of receiver public key')
  }

  const toEncrypt: IEncryptedMessageContents = {
    body: message.body,
    createdAt: message.createdAt,
    sender: message.sender,
    receiver: message.receiver,
    messageId: message.messageId,
    inReplyTo: message.inReplyTo,
    references: message.references,
  }

  const serialized = stringToU8a(JSON.stringify(toEncrypt))

  const encrypted = await encryptCallback({
    did: message.sender,
    data: serialized,
    peerPublicKey,
  })

  const ciphertext = u8aToHex(encrypted.data)
  const nonce = u8aToHex(encrypted.nonce)

  return {
    receivedAt: message.receivedAt,
    ciphertext,
    nonce,
    senderKeyUri: encrypted.keyUri,
    receiverKeyUri,
  }
}
